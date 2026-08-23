"""Access control for the Prometheus metrics endpoint.

/metrics is unauthenticated and excluded from rate limiting, and it exposes
message volumes, queue depth, DKIM/SPF failure rates and endpoint latencies.
These tests pin who may reach it.
"""

import pytest
from fastapi import HTTPException
from fastsmtp.config import Settings
from fastsmtp.metrics.access import client_address_for_metrics, require_metrics_access


@pytest.fixture(autouse=True)
def reset_denial_throttle():
    """Reset the module-global denial throttle between tests.

    Shared mutable state leaking across tests is how a previous bug in this
    repo hid: it changes behaviour silently rather than failing loudly.
    """
    from fastsmtp.metrics import access

    access._denial_log = access._DenialLogThrottle()
    yield
    access._denial_log = access._DenialLogThrottle()


def with_settings(request: "FakeRequest", settings: Settings) -> "FakeRequest":
    """Attach settings to a fake request the way create_app attaches them."""
    request.app.state.settings = settings
    return request


def make_settings(**overrides) -> Settings:
    """Build settings with metrics access overrides."""
    base = {
        "database_url": "sqlite+aiosqlite:///:memory:",
        "root_api_key": "test_key_12345",
    }
    base.update(overrides)
    return Settings(**base)


class FakeRequest:
    """Minimal stand-in exposing only what the access check reads.

    Carries app.state.settings because require_metrics_access resolves settings
    from the application it is serving, so create_app(settings) is honoured.
    """

    def __init__(
        self,
        peer: str | None,
        headers: dict[str, str] | None = None,
        settings: Settings | None = None,
    ):
        self.client = type("Client", (), {"host": peer})() if peer else None
        self.headers = headers or {}
        state = type("State", (), {"settings": settings})()
        self.app = type("App", (), {"state": state})()


class TestClientAddressForMetrics:
    """Which address the allowlist is checked against."""

    def test_uses_socket_peer_by_default(self):
        """Test the socket peer is used when no proxies are trusted."""
        request = FakeRequest("203.0.113.9")
        assert client_address_for_metrics(request, make_settings()) == "203.0.113.9"

    def test_ignores_forwarded_for_from_untrusted_peer(self):
        """Test a spoofed X-Forwarded-For from an untrusted peer is ignored.

        This is the whole point of the trusted-proxy list: without it, anyone
        could assert an allowlisted address and walk through.
        """
        request = FakeRequest("203.0.113.9", {"X-Forwarded-For": "10.0.0.1"})

        assert client_address_for_metrics(request, make_settings()) == "203.0.113.9"

    def test_honours_forwarded_for_from_trusted_proxy(self):
        """Test X-Forwarded-For is used when the peer is a trusted proxy."""
        request = FakeRequest("10.9.9.1", {"X-Forwarded-For": "203.0.113.9"})
        settings = make_settings(metrics_trusted_proxies=["10.9.9.0/24"])

        assert client_address_for_metrics(request, settings) == "203.0.113.9"

    def test_takes_rightmost_untrusted_hop_from_chain(self):
        """Test the nearest untrusted hop is used, not the leftmost claim.

        The leftmost entry is client-supplied and can be forged; only the hops
        appended by trusted proxies are meaningful.
        """
        request = FakeRequest(
            "10.9.9.1",
            {"X-Forwarded-For": "1.2.3.4, 203.0.113.9, 10.9.9.2"},
        )
        settings = make_settings(metrics_trusted_proxies=["10.9.9.0/24"])

        assert client_address_for_metrics(request, settings) == "203.0.113.9"

    def test_missing_client_is_unknown(self):
        """Test a request with no peer resolves to a non-matching address."""
        assert client_address_for_metrics(FakeRequest(None), make_settings()) == "unknown"


class TestRequireMetricsAccess:
    """Whether a request is allowed through."""

    def test_allows_everything_when_unset(self):
        """Test an empty allowlist leaves the endpoint unrestricted."""
        require_metrics_access(with_settings(FakeRequest("203.0.113.9"), make_settings()))

    def test_allows_address_inside_prefix(self):
        """Test an address inside an allowed prefix is permitted."""
        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])
        require_metrics_access(with_settings(FakeRequest("10.1.2.3"), settings))

    def test_allows_exact_address(self):
        """Test a bare allowlist entry permits exactly that address."""
        settings = make_settings(metrics_allowed_ips=["192.0.2.5"])
        require_metrics_access(with_settings(FakeRequest("192.0.2.5"), settings))

    def test_denies_address_outside_allowlist(self):
        """Test an address outside the allowlist is refused with 403."""
        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])

        with pytest.raises(HTTPException) as exc_info:
            require_metrics_access(with_settings(FakeRequest("203.0.113.9"), settings))

        assert exc_info.value.status_code == 403

    def test_denies_unknown_peer_when_restricted(self):
        """Test a request with no resolvable peer is refused when restricted."""
        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])

        with pytest.raises(HTTPException) as exc_info:
            require_metrics_access(with_settings(FakeRequest(None), settings))

        assert exc_info.value.status_code == 403

    def test_allows_ipv6_inside_prefix(self):
        """Test IPv6 allowlisting works."""
        settings = make_settings(metrics_allowed_ips=["2001:db8::/32"])
        require_metrics_access(with_settings(FakeRequest("2001:db8::1"), settings))

    def test_spoofed_forwarded_for_does_not_grant_access(self):
        """Test forging X-Forwarded-For cannot bypass the allowlist."""
        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])
        request = FakeRequest("203.0.113.9", {"X-Forwarded-For": "10.1.2.3"})

        with pytest.raises(HTTPException) as exc_info:
            require_metrics_access(with_settings(request, settings))

        assert exc_info.value.status_code == 403

    def test_trusted_proxy_can_present_an_allowed_client(self):
        """Test a genuine proxy hop resolves to the real client address."""
        settings = make_settings(
            metrics_allowed_ips=["203.0.113.0/24"],
            metrics_trusted_proxies=["10.9.9.0/24"],
        )
        request = FakeRequest("10.9.9.1", {"X-Forwarded-For": "203.0.113.9"})

        require_metrics_access(with_settings(request, settings))

    def test_trusted_proxy_is_not_itself_allowed_by_default(self):
        """Test trusting a proxy does not implicitly allowlist it.

        The two settings answer different questions: one is who may assert a
        client address, the other is which clients may scrape.
        """
        settings = make_settings(
            metrics_allowed_ips=["203.0.113.0/24"],
            metrics_trusted_proxies=["10.9.9.0/24"],
        )

        with pytest.raises(HTTPException):
            require_metrics_access(with_settings(FakeRequest("10.9.9.1"), settings))


class TestMetricsRouteEnforcement:
    """The allowlist must be wired onto the actual route, not merely defined."""

    def _app(self, test_engine, **overrides):
        from fastsmtp.main import create_app
        from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

        # Deliberately no dependency_overrides[get_settings]: the point is that
        # create_app(settings) enforces the allowlist it was handed.
        settings = make_settings(**overrides)
        application = create_app(settings)
        application.state.session_factory = async_sessionmaker(
            test_engine, class_=AsyncSession, expire_on_commit=False
        )
        return application

    async def _scrape(self, app, peer: str, headers: dict[str, str] | None = None):
        import httpx

        transport = httpx.ASGITransport(app=app, client=(peer, 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            return await client.get("/metrics", headers=headers or {})

    async def test_unrestricted_by_default(self, test_engine) -> None:
        """Test /metrics stays open when no allowlist is configured."""
        response = await self._scrape(self._app(test_engine), "203.0.113.9")

        assert response.status_code == 200
        assert "fastsmtp_requests_total" in response.text

    async def test_allowed_address_can_scrape(self, test_engine) -> None:
        """Test an allowlisted address still receives metrics."""
        app = self._app(test_engine, metrics_allowed_ips=["10.0.0.0/8"])

        response = await self._scrape(app, "10.1.2.3")

        assert response.status_code == 200
        assert "fastsmtp_requests_total" in response.text

    async def test_denied_address_gets_403_and_no_metrics(self, test_engine) -> None:
        """Test a refused scrape leaks no metric data in the body."""
        app = self._app(test_engine, metrics_allowed_ips=["10.0.0.0/8"])

        response = await self._scrape(app, "203.0.113.9")

        assert response.status_code == 403
        assert "fastsmtp_" not in response.text

    async def test_forged_forwarded_for_cannot_bypass_the_route(self, test_engine) -> None:
        """Test the header cannot open the route from an untrusted peer."""
        app = self._app(test_engine, metrics_allowed_ips=["10.0.0.0/8"])

        response = await self._scrape(app, "203.0.113.9", {"X-Forwarded-For": "10.1.2.3"})

        assert response.status_code == 403


class TestForgedPeerAddress:
    """The allowlist must survive a proxy layer rewriting the peer address.

    uvicorn enables proxy_headers by default, and its ProxyHeadersMiddleware
    overwrites scope["client"] from the leftmost X-Forwarded-For entry - which is
    attacker-controlled. That happens before this application sees the request,
    so an allowlist reading request.client.host would be checking a forged value.

    ASGITransport has no such layer, so these must run over real TCP.
    """

    async def _scrape_over_tcp(
        self, serve_app, run_blocking, settings, headers, **uvicorn_kwargs
    ) -> int:
        import httpx
        from fastsmtp.main import create_app

        app = create_app(settings)

        async with serve_app(app, **uvicorn_kwargs) as base_url:

            def call() -> int:
                return httpx.get(f"{base_url}/metrics", headers=headers, timeout=10.0).status_code

            return await run_blocking(call)

    async def test_serve_disables_uvicorn_proxy_headers(self) -> None:
        """Test the server's own uvicorn config leaves peer rewriting off.

        FastSMTP resolves X-Forwarded-For itself, gated on metrics_trusted_proxies.
        Letting uvicorn rewrite the peer first would make that gate unreachable.
        """
        import inspect

        from fastsmtp import cli

        source = inspect.getsource(cli.serve)

        assert "proxy_headers=False" in source, (
            "uvicorn.Config must set proxy_headers=False; its default of True "
            "rewrites the peer address from an attacker-controlled header"
        )

    async def test_forged_forwarded_for_cannot_bypass_over_real_tcp(
        self, serve_app, run_blocking
    ) -> None:
        """Test a forged header does not grant access when uvicorn rewrites peers."""
        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])

        status = await self._scrape_over_tcp(
            serve_app,
            run_blocking,
            settings,
            headers={"X-Forwarded-For": "10.1.2.3"},
            proxy_headers=False,
        )

        assert status == 403

    async def test_allowlist_still_works_over_real_tcp(self, serve_app, run_blocking) -> None:
        """Test a genuinely allowed peer is still served over TCP."""
        settings = make_settings(metrics_allowed_ips=["127.0.0.0/8"])

        status = await self._scrape_over_tcp(
            serve_app, run_blocking, settings, headers={}, proxy_headers=False
        )

        assert status == 200


class TestDenialLogThrottle:
    """Denied scrapes must not let an unauthenticated client drive log volume.

    /metrics needs no credential and is excluded from rate limiting, so one
    WARNING per denial is an amplification any client can trigger at will.
    """

    def _throttle(self, **kwargs):
        from fastsmtp.metrics.access import _DenialLogThrottle

        return _DenialLogThrottle(**kwargs)

    def test_first_denial_is_logged_immediately(self):
        """Test the first denial produces a message naming the address.

        An operator tailing logs during an incident must see something at once.
        """
        throttle = self._throttle(window_seconds=60.0)

        message = throttle.record("203.0.113.9", now=1000.0)

        assert message is not None
        assert "203.0.113.9" in message

    def test_further_denials_in_the_window_are_suppressed(self):
        """Test repeat denials inside the window produce nothing to log."""
        throttle = self._throttle(window_seconds=60.0)
        throttle.record("203.0.113.9", now=1000.0)

        assert throttle.record("203.0.113.9", now=1001.0) is None
        assert throttle.record("203.0.113.10", now=1030.0) is None

    def test_next_window_reports_what_was_suppressed(self):
        """Test the count and distinct addresses suppressed are reported."""
        throttle = self._throttle(window_seconds=60.0)
        throttle.record("203.0.113.9", now=1000.0)
        throttle.record("203.0.113.9", now=1001.0)
        throttle.record("203.0.113.10", now=1002.0)

        message = throttle.record("203.0.113.11", now=1061.0)

        assert message is not None
        assert "203.0.113.11" in message
        assert "suppressed 2 further denials" in message

    def test_reports_the_real_interval_not_the_nominal_window(self):
        """Test the roll-up names how long ago the burst actually was.

        A window only closes when the next denial arrives, which can be hours
        later. Saying "in the previous 60s" would make an operator page for an
        event that finished long ago.
        """
        throttle = self._throttle(window_seconds=60.0)
        throttle.record("203.0.113.9", now=1000.0)
        throttle.record("203.0.113.9", now=1001.0)

        message = throttle.record("203.0.113.9", now=1000.0 + 7200.0)

        assert message is not None
        assert "7200s" in message, f"expected the real elapsed interval, got: {message}"
        assert "60s" not in message

    def test_quiet_window_reports_no_suppression(self):
        """Test a window with nothing suppressed does not mention suppression."""
        throttle = self._throttle(window_seconds=60.0)
        throttle.record("203.0.113.9", now=1000.0)

        message = throttle.record("203.0.113.9", now=1061.0)

        assert message is not None
        assert "suppress" not in message.lower()

    def test_tracked_addresses_are_capped(self):
        """Test address rotation cannot grow the throttle's state without limit.

        An attacker cycling source addresses would otherwise turn a memory bound
        into a different amplification.
        """
        throttle = self._throttle(window_seconds=60.0, max_tracked_addresses=4)
        throttle.record("10.0.0.0", now=1000.0)
        for i in range(1, 50):
            throttle.record(f"10.0.0.{i}", now=1000.0 + i * 0.1)

        assert len(throttle._addresses) <= 4

        message = throttle.record("10.0.1.1", now=1100.0)
        assert message is not None
        assert "4+" in message, "a capped count must not be reported as exact"

    def test_concurrent_denials_still_log_once(self):
        """Test the throttle holds when denials arrive on multiple threads.

        require_metrics_access is a sync FastAPI dependency, so FastAPI runs it
        in a threadpool: concurrent scrapes hit this from real threads, not the
        event loop.

        This passes on GIL builds whether or not the state is locked - CPython
        happens to make these updates atomic, which no amount of switch-interval
        tuning could be made to break. It pins the contract for free-threaded
        builds, where that accident does not hold.
        """
        import threading

        throttle = self._throttle(window_seconds=60.0)
        workers = 16
        barrier = threading.Barrier(workers)
        results: list[str | None] = []
        results_lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            message = throttle.record("203.0.113.9", now=1000.0)
            with results_lock:
                results.append(message)

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        logged = [m for m in results if m is not None]
        assert len(logged) == 1, f"expected 1 log line, got {len(logged)}"
        assert throttle._suppressed == workers - 1, "suppressed count must not lose updates"

    def test_window_resets_after_reporting(self):
        """Test each window starts clean rather than accumulating forever."""
        throttle = self._throttle(window_seconds=60.0)
        throttle.record("203.0.113.9", now=1000.0)
        throttle.record("203.0.113.9", now=1001.0)
        throttle.record("203.0.113.9", now=1061.0)

        message = throttle.record("203.0.113.9", now=1122.0)

        assert message is not None
        assert "suppress" not in message.lower()


class TestDenialCounter:
    """Denials stay alertable at fixed cost even while logging is throttled."""

    def test_counter_increments_for_every_denial_including_suppressed(self):
        """Test the counter is not throttled along with the log."""
        from fastsmtp.metrics.definitions import METRICS_SCRAPES_DENIED

        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])
        before = METRICS_SCRAPES_DENIED._value.get()

        for _ in range(5):
            with pytest.raises(HTTPException):
                require_metrics_access(with_settings(FakeRequest("203.0.113.9"), settings))

        assert METRICS_SCRAPES_DENIED._value.get() - before == 5

    def test_counter_unchanged_for_allowed_scrapes(self):
        """Test permitted scrapes do not increment the denial counter."""
        from fastsmtp.metrics.definitions import METRICS_SCRAPES_DENIED

        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])
        before = METRICS_SCRAPES_DENIED._value.get()

        require_metrics_access(with_settings(FakeRequest("10.1.2.3"), settings))

        assert METRICS_SCRAPES_DENIED._value.get() == before


class TestDenialLoggingIsWired:
    """The throttle must actually be used by require_metrics_access."""

    def test_repeated_denials_log_once(self, caplog) -> None:
        """Test a burst of denials produces a single WARNING, not one each."""
        import logging

        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])

        with caplog.at_level(logging.WARNING, logger="fastsmtp.metrics.access"):
            for _ in range(10):
                with pytest.raises(HTTPException):
                    require_metrics_access(with_settings(FakeRequest("203.0.113.9"), settings))

        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1, f"expected 1 throttled warning, got {len(warnings)}"
        assert "203.0.113.9" in warnings[0].getMessage()
