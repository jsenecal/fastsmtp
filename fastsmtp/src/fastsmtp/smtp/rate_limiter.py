"""In-memory rate limiter for SMTP connections and messages."""

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock

from fastsmtp.metrics.definitions import SMTP_RATE_LIMITED

logger = logging.getLogger(__name__)


@dataclass
class RateLimitBucket:
    """Sliding window rate limit bucket."""

    timestamps: list[float] = field(default_factory=list)
    lock: Lock = field(default_factory=Lock)

    def cleanup(self, window_seconds: float) -> None:
        """Remove timestamps older than the window."""
        cutoff = time.time() - window_seconds
        self.timestamps = [ts for ts in self.timestamps if ts > cutoff]

    def count(self, window_seconds: float) -> int:
        """Count requests in the current window."""
        self.cleanup(window_seconds)
        return len(self.timestamps)

    def add(self) -> None:
        """Add a new timestamp."""
        self.timestamps.append(time.time())


class SMTPRateLimiter:
    """Rate limiter for SMTP connections and messages per client IP.

    Uses a sliding window algorithm to track requests per client IP.
    This is an in-memory implementation suitable for single-instance deployments.
    For multi-instance deployments, consider using Redis-based rate limiting.
    """

    def __init__(
        self,
        connections_per_minute: int = 30,
        messages_per_minute: int = 60,
        enabled: bool = True,
    ):
        """Initialize the rate limiter.

        Args:
            connections_per_minute: Max connections per minute per IP
            messages_per_minute: Max messages per minute per IP
            enabled: Whether rate limiting is enabled
        """
        self.connections_per_minute = connections_per_minute
        self.messages_per_minute = messages_per_minute
        self.enabled = enabled
        self._window_seconds = 60.0

        # Track connections and messages per IP
        self._connection_buckets: dict[str, RateLimitBucket] = defaultdict(
            RateLimitBucket
        )
        self._message_buckets: dict[str, RateLimitBucket] = defaultdict(
            RateLimitBucket
        )
        self._global_lock = Lock()

    def _get_bucket(
        self, buckets: dict[str, RateLimitBucket], key: str
    ) -> RateLimitBucket:
        """Get or create a bucket for a key."""
        with self._global_lock:
            if key not in buckets:
                buckets[key] = RateLimitBucket()
            return buckets[key]

    def check_connection(self, client_ip: str) -> tuple[bool, str | None]:
        """Check if a connection is allowed from this IP.

        Args:
            client_ip: Client IP address

        Returns:
            Tuple of (allowed, error_message)
        """
        if not self.enabled:
            return True, None

        bucket = self._get_bucket(self._connection_buckets, client_ip)
        with bucket.lock:
            count = bucket.count(self._window_seconds)
            if count >= self.connections_per_minute:
                logger.warning(
                    f"Rate limit exceeded for {client_ip}: "
                    f"{count}/{self.connections_per_minute} connections/min"
                )
                SMTP_RATE_LIMITED.labels(type="connection").inc()
                return False, "Too many connections, please slow down"
            bucket.add()
            return True, None

    def check_message(self, client_ip: str) -> tuple[bool, str | None]:
        """Check if a message is allowed from this IP.

        Args:
            client_ip: Client IP address

        Returns:
            Tuple of (allowed, error_message)
        """
        if not self.enabled:
            return True, None

        bucket = self._get_bucket(self._message_buckets, client_ip)
        with bucket.lock:
            count = bucket.count(self._window_seconds)
            if count >= self.messages_per_minute:
                logger.warning(
                    f"Rate limit exceeded for {client_ip}: "
                    f"{count}/{self.messages_per_minute} messages/min"
                )
                SMTP_RATE_LIMITED.labels(type="message").inc()
                return False, "Too many messages, please slow down"
            bucket.add()
            return True, None

    def cleanup_old_entries(self) -> None:
        """Remove old entries to prevent memory growth.

        Should be called periodically (e.g., every few minutes).
        """
        with self._global_lock:
            # Clean connection buckets
            empty_keys = []
            for key, bucket in self._connection_buckets.items():
                with bucket.lock:
                    bucket.cleanup(self._window_seconds)
                    if not bucket.timestamps:
                        empty_keys.append(key)
            for key in empty_keys:
                del self._connection_buckets[key]

            # Clean message buckets
            empty_keys = []
            for key, bucket in self._message_buckets.items():
                with bucket.lock:
                    bucket.cleanup(self._window_seconds)
                    if not bucket.timestamps:
                        empty_keys.append(key)
            for key in empty_keys:
                del self._message_buckets[key]

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        with self._global_lock:
            return {
                "enabled": self.enabled,
                "connections_per_minute": self.connections_per_minute,
                "messages_per_minute": self.messages_per_minute,
                "tracked_ips_connections": len(self._connection_buckets),
                "tracked_ips_messages": len(self._message_buckets),
            }


# Global rate limiter instance (created on first use)
_rate_limiter: SMTPRateLimiter | None = None


def get_smtp_rate_limiter() -> SMTPRateLimiter:
    """Get the global SMTP rate limiter instance."""
    global _rate_limiter
    if _rate_limiter is None:
        from fastsmtp.config import get_settings

        settings = get_settings()
        _rate_limiter = SMTPRateLimiter(
            connections_per_minute=settings.smtp_rate_limit_connections_per_minute,
            messages_per_minute=settings.smtp_rate_limit_messages_per_minute,
            enabled=settings.smtp_rate_limit_enabled,
        )
    return _rate_limiter


def reset_rate_limiter() -> None:
    """Reset the rate limiter (for testing)."""
    global _rate_limiter
    _rate_limiter = None
