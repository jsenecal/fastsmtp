"""Tests for API key generation and authentication."""

from fastsmtp.auth.keys import (
    API_KEY_PREFIX,
    generate_api_key,
    hash_api_key,
    hash_api_key_salted,
    verify_api_key,
    verify_api_key_salted,
)


def test_generate_api_key_format():
    """Test API key format."""
    full_key, key_prefix, key_hash, key_salt = generate_api_key()

    # Full key should start with prefix
    assert full_key.startswith(API_KEY_PREFIX)
    assert len(full_key) > len(API_KEY_PREFIX) + 20  # Reasonable length

    # Key prefix should be first 12 chars
    assert key_prefix == full_key[:12]

    # Key hash should be a hex string (PBKDF2 output is 32 bytes = 64 hex chars)
    assert len(key_hash) == 64

    # Key salt should be a hex string (32 bytes = 64 hex chars)
    assert len(key_salt) == 64


def test_generate_api_key_uniqueness():
    """Test API keys are unique."""
    keys = [generate_api_key()[0] for _ in range(100)]  # Get full_key from tuple
    assert len(set(keys)) == 100  # All unique


def test_generate_api_key_unique_salts():
    """Test that each generated key has a unique salt."""
    salts = [generate_api_key()[3] for _ in range(100)]  # Get key_salt from tuple
    assert len(set(salts)) == 100  # All unique


def test_hash_api_key_salted():
    """Test salted API key hashing."""
    full_key, _, _, _ = generate_api_key()
    hash1, salt1 = hash_api_key_salted(full_key)
    hash2, salt2 = hash_api_key_salted(full_key)

    # Same key with different salts should produce different hashes
    assert hash1 != hash2
    assert salt1 != salt2


def test_hash_api_key_salted_deterministic_with_same_salt():
    """Test that salted hashing is deterministic with the same salt."""
    full_key, _, _, _ = generate_api_key()
    hash1, salt1 = hash_api_key_salted(full_key)

    # Same key with same salt should produce same hash
    salt_bytes = bytes.fromhex(salt1)
    hash2, _ = hash_api_key_salted(full_key, salt_bytes)
    assert hash1 == hash2


def test_verify_api_key_salted_valid():
    """Test verifying a valid salted API key."""
    full_key, _, key_hash, key_salt = generate_api_key()
    assert verify_api_key_salted(full_key, key_hash, key_salt) is True


def test_verify_api_key_salted_invalid():
    """Test verifying an invalid salted API key."""
    full_key1, _, key_hash1, key_salt1 = generate_api_key()
    full_key2, _, _, _ = generate_api_key()

    # Different key should not verify
    assert verify_api_key_salted(full_key2, key_hash1, key_salt1) is False


def test_verify_api_key_salted_wrong_salt():
    """Test that wrong salt fails verification."""
    full_key, _, key_hash, key_salt = generate_api_key()
    _, _, _, wrong_salt = generate_api_key()

    assert verify_api_key_salted(full_key, key_hash, wrong_salt) is False


def test_verify_api_key_salted_corrupted():
    """Test verifying corrupted salted API key."""
    full_key, _, key_hash, key_salt = generate_api_key()

    # Modify key slightly
    corrupted_key = full_key[:-1] + "X"
    assert verify_api_key_salted(corrupted_key, key_hash, key_salt) is False


# Legacy function tests (for backward compatibility)
def test_hash_api_key_legacy():
    """Test legacy API key hashing (unsalted)."""
    full_key, _, _, _ = generate_api_key()
    hashed = hash_api_key(full_key)

    # Hash should be different from original
    assert hashed != full_key

    # Hash should be deterministic (same key = same hash)
    assert hash_api_key(full_key) == hashed


def test_verify_api_key_legacy_valid():
    """Test verifying a valid legacy API key."""
    full_key, _, _, _ = generate_api_key()
    key_hash = hash_api_key(full_key)
    assert verify_api_key(full_key, key_hash) is True


def test_verify_api_key_legacy_invalid():
    """Test verifying an invalid legacy API key."""
    full_key1, _, _, _ = generate_api_key()
    full_key2, _, _, _ = generate_api_key()
    key_hash1 = hash_api_key(full_key1)

    assert verify_api_key(full_key2, key_hash1) is False
