"""Encryption utilities for sensitive data at rest."""

import base64
import hashlib
from typing import cast

from cryptography.fernet import Fernet


def _derive_fernet_key(key: str) -> bytes:
    """Derive a Fernet-compatible key from a user-provided key.

    Fernet requires a 32-byte URL-safe base64-encoded key.
    We hash the user's key to ensure consistent length.
    """
    key_bytes = hashlib.sha256(key.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_data(plaintext: str | None, key: str | None) -> str | None:
    """Encrypt a string value.

    Args:
        plaintext: The string to encrypt. Returns None if None.
        key: The encryption key. If None, returns plaintext unchanged (passthrough).

    Returns:
        Encrypted string (base64 encoded) or original value if no key.
    """
    if plaintext is None:
        return None
    if key is None:
        return plaintext

    fernet_key = _derive_fernet_key(key)
    f = Fernet(fernet_key)
    encrypted = f.encrypt(plaintext.encode())
    return encrypted.decode()


def decrypt_data(ciphertext: str | None, key: str | None) -> str | None:
    """Decrypt an encrypted string value.

    Args:
        ciphertext: The encrypted string to decrypt. Returns None if None.
        key: The encryption key. If None, returns ciphertext unchanged (passthrough).

    Returns:
        Decrypted string or original value if no key.

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails (wrong key or corrupted data).
    """
    if ciphertext is None:
        return None
    if key is None:
        return ciphertext

    fernet_key = _derive_fernet_key(key)
    f = Fernet(fernet_key)
    decrypted = f.decrypt(ciphertext.encode())
    return decrypted.decode()


def encrypt_dict(data: dict[str, str] | None, key: str | None) -> dict[str, str] | None:
    """Encrypt all string values in a dictionary.

    Args:
        data: Dictionary with string values to encrypt. Returns None if None.
        key: The encryption key. If None, returns data unchanged (passthrough).

    Returns:
        Dictionary with encrypted values or original dict if no key.
    """
    if data is None:
        return None
    if key is None:
        return data

    return {k: cast(str, encrypt_data(v, key)) for k, v in data.items()}


def decrypt_dict(data: dict[str, str] | None, key: str | None) -> dict[str, str] | None:
    """Decrypt all string values in a dictionary.

    Args:
        data: Dictionary with encrypted values to decrypt. Returns None if None.
        key: The encryption key. If None, returns data unchanged (passthrough).

    Returns:
        Dictionary with decrypted values or original dict if no key.
    """
    if data is None:
        return None
    if key is None:
        return data

    return {k: cast(str, decrypt_data(v, key)) for k, v in data.items()}
