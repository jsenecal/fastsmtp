"""Tests for API key generation and authentication."""


from fastsmtp.auth.keys import (
    API_KEY_PREFIX,
    generate_api_key,
    hash_api_key,
    verify_api_key,
)


def test_generate_api_key_format():
    """Test API key format."""
    full_key, key_prefix, key_hash = generate_api_key()

    # Full key should start with prefix
    assert full_key.startswith(API_KEY_PREFIX)
    assert len(full_key) > len(API_KEY_PREFIX) + 20  # Reasonable length

    # Key prefix should be first 12 chars
    assert key_prefix == full_key[:12]

    # Key hash should be a hex string
    assert len(key_hash) == 64  # SHA256 hex is 64 chars


def test_generate_api_key_uniqueness():
    """Test API keys are unique."""
    keys = [generate_api_key()[0] for _ in range(100)]  # Get full_key from tuple
    assert len(set(keys)) == 100  # All unique


def test_hash_api_key():
    """Test API key hashing."""
    full_key, _, _ = generate_api_key()
    hashed = hash_api_key(full_key)

    # Hash should be different from original
    assert hashed != full_key

    # Hash should be deterministic
    assert hash_api_key(full_key) == hashed


def test_verify_api_key_valid():
    """Test verifying a valid API key."""
    full_key, _, key_hash = generate_api_key()
    assert verify_api_key(full_key, key_hash) is True


def test_verify_api_key_invalid():
    """Test verifying an invalid API key."""
    full_key1, _, key_hash1 = generate_api_key()
    full_key2, _, _ = generate_api_key()

    assert verify_api_key(full_key2, key_hash1) is False


def test_verify_api_key_corrupted():
    """Test verifying corrupted API key."""
    full_key, _, key_hash = generate_api_key()

    # Modify key slightly
    corrupted_key = full_key[:-1] + "X"
    assert verify_api_key(corrupted_key, key_hash) is False
