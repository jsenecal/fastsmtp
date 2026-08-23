"""Access control for the Prometheus metrics endpoint.

/metrics is unauthenticated and excluded from rate limiting, and what it exposes
is operationally sensitive: message volumes, queue depth, DKIM/SPF failure rates
and per-endpoint latencies. Deployments that cannot keep the API port on a
private network need a way to restrict who may scrape it.
"""

import logging
import threading
import time

from fastapi import HTTPException, Request, status

from fastsmtp.config import Settings, get_settings
from fastsmtp.metrics.definitions import METRICS_SCRAPES_DENIED
from fastsmtp.net import ip_in_networks, parse_networks

logger = logging.getLogger(__name__)

#: How long denials are collapsed into a single log line.
DENIAL_LOG_WINDOW_SECONDS = 60.0

#: Distinct addresses remembered per window, so rotating source addresses
#: cannot turn log throttling into unbounded memory growth.
DENIAL_LOG_MAX_ADDRESSES = 32


class _DenialLogThrottle:
    """Collapse repeated denials into one log line per window.

    /metrics needs no credential and is excluded from rate limiting, so logging
    every denial lets any client drive unbounded log volume. The first denial in
    a window is logged at once - an operator tailing logs during an incident
    needs to see it - and the rest are counted and reported when the window
    rolls over.

    State is per-process, so a deployment running several workers gets one
    window per worker. That does not change the bound.

    require_metrics_access is a sync dependency, so FastAPI dispatches it to a
    threadpool and concurrent scrapes reach this from real threads. CPython's
    GIL happens to make these particular updates atomic, but that is an
    implementation detail rather than a guarantee - and not one that holds on
    free-threaded builds - so the state is lock-protected.

    The rolled-up count is reported by the *next* denial, so if an attack stops
    mid-window its tail is not reported until something triggers again.
    fastsmtp_metrics_scrapes_denied_total is not throttled and covers that gap.
    """

    def __init__(
        self,
        window_seconds: float = DENIAL_LOG_WINDOW_SECONDS,
        max_tracked_addresses: int = DENIAL_LOG_MAX_ADDRESSES,
    ):
        self.window_seconds = window_seconds
        self.max_tracked_addresses = max_tracked_addresses
        self._lock = threading.Lock()
        self._window_start: float | None = None
        self._suppressed = 0
        self._addresses: set[str] = set()

    def record(self, address: str, now: float) -> str | None:
        """Register a denial and return the line to log, if any.

        Args:
            address: Client address that was refused
            now: Monotonic timestamp, passed in so windows are testable

        Returns:
            A message to log, or None while the current window is suppressing.
        """
        with self._lock:
            if self._window_start is not None and now - self._window_start < self.window_seconds:
                self._suppressed += 1
                if len(self._addresses) < self.max_tracked_addresses:
                    self._addresses.add(address)
                return None

            suppressed, distinct = self._suppressed, len(self._addresses)
            capped = distinct >= self.max_tracked_addresses
            elapsed = now - self._window_start if self._window_start is not None else 0.0
            self._window_start = now
            self._suppressed = 0
            self._addresses = set()

        if not suppressed:
            return f"Denied metrics scrape from {address}"

        count = f"{distinct}+" if capped else str(distinct)
        # The elapsed interval, not the nominal window: a window only closes when
        # the next denial arrives, which can be far later. Reporting "60s" for a
        # burst that ended hours ago would page someone for a finished event.
        return (
            f"Denied metrics scrape from {address} "
            f"(suppressed {suppressed} further denials from {count} "
            f"addresses in the preceding {elapsed:.0f}s)"
        )


_denial_log = _DenialLogThrottle()


def client_address_for_metrics(request: Request, settings: Settings) -> str:
    """Resolve the address the metrics allowlist should be checked against.

    ``X-Forwarded-For`` is attacker-controlled unless a proxy you trust appended
    it, so it is consulted only when the socket peer is listed in
    ``metrics_trusted_proxies``. The chain is then walked from the right,
    discarding trusted hops, and the first untrusted entry is the client: the
    leftmost entry is whatever the original caller chose to send.

    This deliberately does not reuse ``middleware.rate_limit._get_client_ip``,
    which trusts the header unconditionally. That is tolerable for rate-limit
    bucketing but would make this allowlist trivially bypassable.

    Args:
        request: Incoming request
        settings: Application settings

    Returns:
        The client address, or ``"unknown"`` when no peer can be determined.
    """
    peer = request.client.host if request.client else None
    if peer is None:
        return "unknown"

    trusted = parse_networks(settings.metrics_trusted_proxies)
    if not trusted or not ip_in_networks(peer, trusted):
        return peer

    forwarded = request.headers.get("X-Forwarded-For")
    if not forwarded:
        return peer

    for hop in reversed([h.strip() for h in forwarded.split(",") if h.strip()]):
        if not ip_in_networks(hop, trusted):
            return hop

    # Every hop was a trusted proxy, so no client address was ever asserted.
    return peer


def _settings_for(request: Request) -> Settings:
    """Prefer the settings create_app was given over the cached globals.

    create_app(settings) stores them on app.state, and an access control must
    honour the configuration it was handed rather than whatever the process
    environment happened to cache.
    """
    return getattr(request.app.state, "settings", None) or get_settings()


def require_metrics_access(request: Request) -> None:
    """Reject metrics scrapes from addresses outside the allowlist.

    An empty ``metrics_allowed_ips`` leaves the endpoint unrestricted, which is
    the historical behaviour.

    Raises:
        HTTPException: 403 if the resolved client address is not allowed.
    """
    settings = _settings_for(request)
    allowed = parse_networks(settings.metrics_allowed_ips)
    if not allowed:
        return

    client = client_address_for_metrics(request, settings)
    if ip_in_networks(client, allowed):
        return

    METRICS_SCRAPES_DENIED.inc()
    message = _denial_log.record(client, now=time.monotonic())
    if message is not None:
        logger.warning("%s", message)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Metrics access is not permitted from this address",
    )
