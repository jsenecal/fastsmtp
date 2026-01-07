"""Rate limiting middleware using Redis/Valkey backend."""

import logging
import time
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from fastsmtp.config import get_settings

logger = logging.getLogger(__name__)

# Module-level Redis client
_redis_client = None


async def get_redis_client():
    """Get or create Redis client (lazy initialization)."""
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        if settings.redis_url:
            try:
                import redis.asyncio as redis

                _redis_client = redis.from_url(
                    settings.redis_url,
                    encoding="utf-8",
                    decode_responses=False,
                )
            except ImportError:
                logger.warning("redis package not installed, rate limiting disabled")
                return None
            except Exception as e:
                logger.warning(f"Failed to connect to Redis: {e}")
                return None
    return _redis_client


async def close_redis_client():
    """Close the Redis client."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, considering proxies."""
    # Check X-Forwarded-For first (for proxies)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    # Fall back to direct client IP
    if request.client:
        return request.client.host
    return "unknown"


def _get_api_key_id(request: Request) -> str | None:
    """Extract API key identifier from request (first 12 chars for privacy)."""
    api_key = request.headers.get("X-API-Key", "")
    if len(api_key) >= 12:
        return api_key[:12]
    return None


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting API requests using Redis.

    Rate limits:
    - API requests: per API key (default 100/min)
    - Auth attempts: per IP for requests without valid API key (default 5/min)
    """

    # Paths to exclude from rate limiting
    EXCLUDED_PATHS = {"/metrics", "/api/v1/health", "/api/v1/ready"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request with rate limiting."""
        settings = get_settings()

        # Skip if rate limiting is disabled or Redis not configured
        if not settings.rate_limit_enabled or not settings.redis_url:
            return await call_next(request)

        # Skip excluded paths
        if request.url.path in self.EXCLUDED_PATHS:
            return await call_next(request)

        # Get Redis client
        redis_client = await get_redis_client()
        if redis_client is None:
            # Redis unavailable, allow request
            return await call_next(request)

        # Determine rate limit key and limit
        api_key_id = _get_api_key_id(request)
        client_ip = _get_client_ip(request)

        if api_key_id:
            # Rate limit by API key
            rate_key = f"rate_limit:api:{api_key_id}"
            limit = settings.rate_limit_requests_per_minute
        else:
            # Rate limit by IP (for auth attempts)
            rate_key = f"rate_limit:ip:{client_ip}"
            limit = settings.rate_limit_auth_attempts_per_minute

        # Check and increment rate limit
        try:
            current = await redis_client.get(rate_key)
            current_count = int(current) if current else 0

            if current_count >= limit:
                # Rate limit exceeded
                reset_time = await redis_client.ttl(rate_key)
                if reset_time < 0:
                    reset_time = 60

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded",
                        "retry_after": reset_time,
                    },
                    headers={
                        "Retry-After": str(reset_time),
                        "X-RateLimit-Limit": str(limit),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(time.time()) + reset_time),
                    },
                )

            # Increment counter
            pipe = redis_client.pipeline()
            pipe.incr(rate_key)
            pipe.expire(rate_key, 60)  # 1 minute window
            await pipe.execute()

            new_count = current_count + 1
            remaining = max(0, limit - new_count)

            # Process request
            response = await call_next(request)

            # Add rate limit headers
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)

            return response

        except Exception as e:
            logger.warning(f"Rate limiting error: {e}")
            # On error, allow request
            return await call_next(request)
