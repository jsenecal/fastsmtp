"""Prometheus metrics middleware for FastAPI."""

import time
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from fastsmtp.metrics.definitions import REQUEST_DURATION, REQUEST_TOTAL


def _get_path_template(request: Request) -> str:
    """Get the path template for metrics labeling.

    Returns the route path pattern instead of the actual path
    to avoid high cardinality from path parameters.
    """
    # Try to get the route path template from the matched route
    if hasattr(request, "scope") and "route" in request.scope:
        route = request.scope["route"]
        if hasattr(route, "path"):
            return route.path

    # Fall back to the actual path (but normalize common patterns)
    path = request.url.path

    # Remove trailing slashes for consistency
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    return path


class MetricsMiddleware(BaseHTTPMiddleware):
    """Middleware that collects Prometheus metrics for HTTP requests.

    Metrics collected:
    - fastsmtp_requests_total: Counter of total requests by method, endpoint, status
    - fastsmtp_request_duration_seconds: Histogram of request durations
    """

    # Paths to exclude from metrics (to avoid self-referential metrics)
    EXCLUDED_PATHS = {"/metrics", "/api/v1/health", "/api/v1/ready"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and collect metrics."""
        # Skip metrics collection for excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)

        # Record start time
        start_time = time.perf_counter()

        # Process the request
        response: Response = await call_next(request)

        # Calculate duration
        duration = time.perf_counter() - start_time

        # Get path template for labeling
        path_template = _get_path_template(request)

        # Record metrics
        REQUEST_TOTAL.labels(
            method=request.method,
            endpoint=path_template,
            status_code=response.status_code,
        ).inc()

        REQUEST_DURATION.labels(
            method=request.method,
            endpoint=path_template,
        ).observe(duration)

        return response
