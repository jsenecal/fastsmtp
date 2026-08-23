"""Access control for the Prometheus metrics endpoint.

/metrics is unauthenticated and excluded from rate limiting, and what it exposes
is operationally sensitive: message volumes, queue depth, DKIM/SPF failure rates
and per-endpoint latencies. Deployments that cannot keep the API port on a
private network need a way to restrict who may scrape it.
"""

import logging

from fastapi import HTTPException, Request, status

from fastsmtp.config import Settings, get_settings
from fastsmtp.net import ip_in_networks, parse_networks

logger = logging.getLogger(__name__)


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

    logger.warning("Denied metrics scrape from %s", client)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Metrics access is not permitted from this address",
    )
