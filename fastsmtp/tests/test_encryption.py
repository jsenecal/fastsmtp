"""Tests for webhook header encryption.

Tests follow TDD - written before implementation.
"""

import pytest

from fastsmtp.config import Settings


class TestEncryptionConfig:
    """Test encryption configuration."""

    def test_settings_has_encryption_key_field(self):
        """Settings should have an encryption_key field."""
        settings = Settings(
            root_api_key="test123",
            encryption_key="test-encryption-key-32-bytes-long!",
        )

        assert hasattr(settings, "encryption_key")
        assert settings.encryption_key is not None

    def test_encryption_key_is_optional(self):
        """Encryption key should be optional (for backward compatibility)."""
        settings = Settings(root_api_key="test123")

        assert hasattr(settings, "encryption_key")
        # Should be None or have a default


class TestEncryptionUtilities:
    """Test encryption utility functions."""

    def test_encrypt_function_exists(self):
        """There should be an encrypt_data function."""
        from fastsmtp.crypto import encrypt_data

        assert callable(encrypt_data)

    def test_decrypt_function_exists(self):
        """There should be a decrypt_data function."""
        from fastsmtp.crypto import decrypt_data

        assert callable(decrypt_data)

    def test_encrypt_returns_different_value(self):
        """Encrypted data should be different from plaintext."""
        from fastsmtp.crypto import encrypt_data

        plaintext = "secret-api-key-value"
        key = "test-encryption-key-32-bytes-ok!"

        encrypted = encrypt_data(plaintext, key)

        assert encrypted != plaintext
        assert encrypted is not None

    def test_decrypt_returns_original_value(self):
        """Decrypted data should match original plaintext."""
        from fastsmtp.crypto import decrypt_data, encrypt_data

        plaintext = "secret-api-key-value"
        key = "test-encryption-key-32-bytes-ok!"

        encrypted = encrypt_data(plaintext, key)
        decrypted = decrypt_data(encrypted, key)

        assert decrypted == plaintext

    def test_encrypt_empty_string(self):
        """Encrypting empty string should work."""
        from fastsmtp.crypto import decrypt_data, encrypt_data

        plaintext = ""
        key = "test-encryption-key-32-bytes-ok!"

        encrypted = encrypt_data(plaintext, key)
        decrypted = decrypt_data(encrypted, key)

        assert decrypted == plaintext

    def test_encrypt_none_returns_none(self):
        """Encrypting None should return None."""
        from fastsmtp.crypto import encrypt_data

        key = "test-encryption-key-32-bytes-ok!"

        result = encrypt_data(None, key)

        assert result is None

    def test_decrypt_none_returns_none(self):
        """Decrypting None should return None."""
        from fastsmtp.crypto import decrypt_data

        key = "test-encryption-key-32-bytes-ok!"

        result = decrypt_data(None, key)

        assert result is None

    def test_decrypt_with_wrong_key_fails(self):
        """Decrypting with wrong key should raise an error."""
        from fastsmtp.crypto import decrypt_data, encrypt_data

        plaintext = "secret-api-key-value"
        key1 = "test-encryption-key-32-bytes-ok!"
        key2 = "different-key-also-32-bytes-ok!!"

        encrypted = encrypt_data(plaintext, key1)

        with pytest.raises(Exception):  # Could be InvalidToken or similar
            decrypt_data(encrypted, key2)


class TestEncryptDict:
    """Test dictionary encryption for webhook headers."""

    def test_encrypt_dict_function_exists(self):
        """There should be an encrypt_dict function."""
        from fastsmtp.crypto import encrypt_dict

        assert callable(encrypt_dict)

    def test_decrypt_dict_function_exists(self):
        """There should be a decrypt_dict function."""
        from fastsmtp.crypto import decrypt_dict

        assert callable(decrypt_dict)

    def test_encrypt_dict_returns_encrypted_values(self):
        """Encrypting dict should encrypt all string values."""
        from fastsmtp.crypto import encrypt_dict

        headers = {
            "Authorization": "Bearer secret-token",
            "X-API-Key": "api-key-12345",
        }
        key = "test-encryption-key-32-bytes-ok!"

        encrypted = encrypt_dict(headers, key)

        # Values should be different (encrypted)
        assert encrypted["Authorization"] != headers["Authorization"]
        assert encrypted["X-API-Key"] != headers["X-API-Key"]

    def test_decrypt_dict_returns_original_values(self):
        """Decrypting dict should return original values."""
        from fastsmtp.crypto import decrypt_dict, encrypt_dict

        headers = {
            "Authorization": "Bearer secret-token",
            "X-API-Key": "api-key-12345",
        }
        key = "test-encryption-key-32-bytes-ok!"

        encrypted = encrypt_dict(headers, key)
        decrypted = decrypt_dict(encrypted, key)

        assert decrypted == headers

    def test_encrypt_empty_dict(self):
        """Encrypting empty dict should return empty dict."""
        from fastsmtp.crypto import encrypt_dict

        headers: dict = {}
        key = "test-encryption-key-32-bytes-ok!"

        encrypted = encrypt_dict(headers, key)

        assert encrypted == {}

    def test_encrypt_dict_none_returns_none(self):
        """Encrypting None dict should return None."""
        from fastsmtp.crypto import encrypt_dict

        key = "test-encryption-key-32-bytes-ok!"

        result = encrypt_dict(None, key)

        assert result is None

    def test_decrypt_dict_none_returns_none(self):
        """Decrypting None dict should return None."""
        from fastsmtp.crypto import decrypt_dict

        key = "test-encryption-key-32-bytes-ok!"

        result = decrypt_dict(None, key)

        assert result is None


class TestEncryptionWithoutKey:
    """Test behavior when encryption key is not configured."""

    def test_encrypt_without_key_returns_original(self):
        """Encrypting without a key should return original value (passthrough)."""
        from fastsmtp.crypto import encrypt_data

        plaintext = "secret-value"

        # None key should passthrough
        result = encrypt_data(plaintext, None)

        assert result == plaintext

    def test_decrypt_without_key_returns_original(self):
        """Decrypting without a key should return original value (passthrough)."""
        from fastsmtp.crypto import decrypt_data

        ciphertext = "some-value"

        # None key should passthrough
        result = decrypt_data(ciphertext, None)

        assert result == ciphertext

    def test_encrypt_dict_without_key_returns_original(self):
        """Encrypting dict without key should return original dict."""
        from fastsmtp.crypto import encrypt_dict

        headers = {"Authorization": "Bearer token"}

        result = encrypt_dict(headers, None)

        assert result == headers

    def test_decrypt_dict_without_key_returns_original(self):
        """Decrypting dict without key should return original dict."""
        from fastsmtp.crypto import decrypt_dict

        headers = {"Authorization": "Bearer token"}

        result = decrypt_dict(headers, None)

        assert result == headers
