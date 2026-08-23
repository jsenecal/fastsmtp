"""Access control for the Prometheus metrics endpoint.

/metrics is unauthenticated and excluded from rate limiting, and it exposes
message volumes, queue depth, DKIM/SPF failure rates and endpoint latencies.
These tests pin who may reach it.
"""

import pytest
from fastapi import HTTPException
from fastsmtp.config import Settings
from fastsmtp.metrics.access import client_address_for_metrics, require_metrics_access


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

    The server setup below is local because it needs custom uvicorn options.
    PR #58 extracts a shared serving() helper into conftest; once that lands
    this should take its uvicorn kwargs through it rather than keep a copy.
    """

    async def _scrape_over_tcp(self, settings, headers, **uvicorn_kwargs) -> int:
        import asyncio

        import anyio
        import httpx
        import uvicorn
        from fastsmtp.main import create_app

        app = create_app(settings)

        config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="error", **uvicorn_kwargs)
        server = uvicorn.Server(config)
        server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
        serving = asyncio.create_task(server.serve())
        deadline = asyncio.get_running_loop().time() + 10.0
        while not server.started:
            if serving.done():  # pragma: no cover - startup failure
                serving.result()
                raise RuntimeError("uvicorn server exited before starting")
            if asyncio.get_running_loop().time() > deadline:  # pragma: no cover
                serving.cancel()
                raise TimeoutError("uvicorn did not start within 10s")
            await anyio.sleep(0.02)
        port = server.servers[0].sockets[0].getsockname()[1]

        def call() -> int:
            return httpx.get(
                f"http://127.0.0.1:{port}/metrics", headers=headers, timeout=10.0
            ).status_code

        try:
            return await anyio.to_thread.run_sync(call)
        finally:
            server.should_exit = True
            await asyncio.wait_for(serving, timeout=10)

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

    async def test_forged_forwarded_for_cannot_bypass_over_real_tcp(self) -> None:
        """Test a forged header does not grant access when uvicorn rewrites peers."""
        settings = make_settings(metrics_allowed_ips=["10.0.0.0/8"])

        status = await self._scrape_over_tcp(
            settings,
            headers={"X-Forwarded-For": "10.1.2.3"},
            proxy_headers=False,
        )

        assert status == 403

    async def test_allowlist_still_works_over_real_tcp(self) -> None:
        """Test a genuinely allowed peer is still served over TCP."""
        settings = make_settings(metrics_allowed_ips=["127.0.0.0/8"])

        status = await self._scrape_over_tcp(settings, headers={}, proxy_headers=False)

        assert status == 200
