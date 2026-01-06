"""API key generation and hashing utilities."""

import hashlib
import secrets
from datetime import datetime

API_KEY_PREFIX = "fsmtp_"
API_KEY_LENGTH = 32


def generate_api_key() -> tuple[str, str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (full_key, key_prefix, key_hash)
    """
    random_part = secrets.token_urlsafe(API_KEY_LENGTH)
    full_key = f"{API_KEY_PREFIX}{random_part}"
    key_prefix = full_key[:12]
    key_hash = hash_api_key(full_key)
    return full_key, key_prefix, key_hash


def hash_api_key(key: str, algorithm: str = "sha256") -> str:
    """Hash an API key for secure storage.

    Args:
        key: The full API key to hash
        algorithm: Hash algorithm to use (default: sha256)

    Returns:
        Hex-encoded hash of the key
    """
    hasher = hashlib.new(algorithm)
    hasher.update(key.encode("utf-8"))
    return hasher.hexdigest()


def verify_api_key(key: str, key_hash: str, algorithm: str = "sha256") -> bool:
    """Verify an API key against its hash.

    Args:
        key: The full API key to verify
        key_hash: The stored hash to compare against
        algorithm: Hash algorithm used (default: sha256)

    Returns:
        True if the key matches the hash
    """
    return secrets.compare_digest(hash_api_key(key, algorithm), key_hash)


def is_key_expired(expires_at: datetime | None) -> bool:
    """Check if an API key has expired.

    Args:
        expires_at: Expiration datetime or None for no expiration

    Returns:
        True if the key is expired
    """
    if expires_at is None:
        return False
    return datetime.now(expires_at.tzinfo) > expires_at
