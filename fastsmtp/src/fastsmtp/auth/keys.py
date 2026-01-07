"""API key generation and hashing utilities."""

import hashlib
import secrets
from datetime import datetime

API_KEY_PREFIX = "fsmtp_"
API_KEY_LENGTH = 32
PBKDF2_ITERATIONS = 100_000
SALT_LENGTH = 32


def generate_api_key() -> tuple[str, str, str, str]:
    """Generate a new API key with salted hash.

    Returns:
        Tuple of (full_key, key_prefix, key_hash, key_salt)
    """
    random_part = secrets.token_urlsafe(API_KEY_LENGTH)
    full_key = f"{API_KEY_PREFIX}{random_part}"
    key_prefix = full_key[:12]
    key_hash, key_salt = hash_api_key_salted(full_key)
    return full_key, key_prefix, key_hash, key_salt


def hash_api_key_salted(key: str, salt: bytes | None = None) -> tuple[str, str]:
    """Hash an API key with salt using PBKDF2.

    Args:
        key: The full API key to hash
        salt: Optional salt bytes. If None, generates a new random salt.

    Returns:
        Tuple of (hash_hex, salt_hex)
    """
    if salt is None:
        salt = secrets.token_bytes(SALT_LENGTH)

    key_hash = hashlib.pbkdf2_hmac(
        "sha256",
        key.encode("utf-8"),
        salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return key_hash.hex(), salt.hex()


def verify_api_key_salted(key: str, stored_hash: str, stored_salt: str) -> bool:
    """Verify an API key against its salted hash.

    Args:
        key: The full API key to verify
        stored_hash: The stored hash to compare against
        stored_salt: The stored salt (hex-encoded)

    Returns:
        True if the key matches the hash
    """
    salt = bytes.fromhex(stored_salt)
    computed_hash, _ = hash_api_key_salted(key, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


# Legacy functions for backward compatibility during migration
def hash_api_key(key: str, algorithm: str = "sha256") -> str:
    """Hash an API key for secure storage (LEGACY - unsalted).

    DEPRECATED: Use hash_api_key_salted() for new keys.

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
    """Verify an API key against its hash (LEGACY - unsalted).

    DEPRECATED: Use verify_api_key_salted() for salted keys.

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
