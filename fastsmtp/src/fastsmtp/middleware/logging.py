"""Request logging middleware for API observability."""

import logging
import time
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("fastsmtp.access")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs incoming HTTP requests.

    Logs:
    - Request method and path
    - Response status code
    - Response time in milliseconds
    - Client IP address
    - API key identifier (prefix only, not the full key)
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log details."""
        start_time = time.perf_counter()

        # Extract client IP
        client_ip = request.client.host if request.client else "unknown"

        # Check for forwarded IP (behind proxy/load balancer)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            # Take the first IP in the chain (original client)
            client_ip = forwarded_for.split(",")[0].strip()

        # Extract API key identifier (prefix only for security)
        api_key_header = request.headers.get("X-API-Key", "")
        api_key_id = api_key_header[:12] if len(api_key_header) >= 12 else "none"

        # Process the request
        response: Response = await call_next(request)

        # Calculate response time
        process_time_ms = (time.perf_counter() - start_time) * 1000

        # Log the request
        # Format: IP METHOD PATH STATUS TIME_MS KEY_PREFIX
        logger.info(
            "%s %s %s %d %.2fms key=%s",
            client_ip,
            request.method,
            request.url.path,
            response.status_code,
            process_time_ms,
            api_key_id,
        )

        # Add timing header
        response.headers["X-Process-Time-Ms"] = f"{process_time_ms:.2f}"

        return response
