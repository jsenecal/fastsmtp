"""Envelope encryption for sensitive JSON columns at rest.

``recipients.webhook_headers`` holds third-party bearer tokens, so the column
is encrypted in the database while staying an ordinary JSON object everywhere
else. Encryption happens at the SQLAlchemy storage layer, which is why this
module is deliberately free of SQLAlchemy imports: it maps a plain ``dict`` to
a plain ``dict`` and knows nothing about sessions, columns or dialects.

The stored form is an envelope::

    {"__fastsmtp_encrypted__": 1, "ciphertext": "gAAAAAB..."}

The envelope is itself JSON-serializable so it can live in a JSONB column
without any dialect-level help, and the marker makes an encrypted row
distinguishable from a legacy plaintext one. That distinction is what allows a
rollout with no downtime: rows written before the feature was enabled are
returned unchanged, and are rewritten as envelopes the next time they are
saved.

Keys come from the operator in priority order. The first key encrypts; every
key decrypts. That is exactly ``MultiFernet``'s contract, and it is what makes
rotation possible: an operator prepends a new key, rewrites the stored rows
(``fastsmtp encrypt-existing``), then removes the old one.
"""

import base64
import hashlib
import json
from collections.abc import Sequence
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

#: Key present on a stored envelope, and only on a stored envelope. Named
#: distinctively so it cannot collide with a real webhook header name.
ENVELOPE_MARKER = "__fastsmtp_encrypted__"

#: Value of the marker. Bumped only if the envelope layout changes; an
#: unrecognised version is refused rather than guessed at.
ENVELOPE_VERSION = 1

#: Name of the setting operators populate, quoted in errors so the message
#: points at the fix rather than at this module.
KEYS_SETTING = "FASTSMTP_ENCRYPTION_KEYS"

#: Work factor for turning an operator's key string into a Fernet key. Matches
#: the API key hashing in ``auth/keys.py``, deliberately: both take a secret
#: whose entropy this code cannot vouch for and must not make cheap to guess.
_KDF_ITERATIONS = 100_000

#: Fixed salt. The derivation has to be reproducible from the key alone, across
#: processes and restarts, with nothing persisted -- so there is nowhere to keep
#: a per-deployment random salt. A constant salt does not defeat precomputation
#: the way a random one would, which is why the documentation tells operators to
#: generate a random key rather than choose a memorable one. The work factor is
#: the backstop for when they do it anyway.
_KDF_SALT = b"fastsmtp.column-encryption.v1"


class EncryptionError(RuntimeError):
    """Base class for every failure raised by this module."""


class KeyConfigurationError(EncryptionError):
    """The configured key material is unusable."""


class DecryptionError(EncryptionError):
    """A stored value could not be turned back into plaintext.

    Always raised rather than degrading to an empty value. The encrypted
    columns hold credentials, and a silent downgrade would mean dispatching a
    webhook with no authentication headers at all - a request that looks
    successful to the caller and is rejected, or worse accepted anonymously,
    by the receiver.
    """


def _derive_fernet_key(key: str) -> bytes:
    """Derive a Fernet key from an arbitrary operator-supplied string.

    Fernet wants 32 bytes of URL-safe base64. Deriving means an operator can
    use any passphrase or secret-manager value without having to generate a
    base64 key of exactly the right length first.

    That convenience is also the reason this uses a slow KDF rather than a
    plain hash. Accepting any string invites a memorable one, and the threat
    this whole module defends against is an attacker holding the database.
    Against a single SHA-256 they could try billions of candidate passphrases a
    second; at 100k PBKDF2 iterations the same search costs five orders of
    magnitude more. The cost is paid once per distinct key set per process,
    because ``encryption.get_cipher`` caches the built cipher - not once per
    row.

    Args:
        key: The raw string from configuration

    Returns:
        A URL-safe base64 key accepted by ``Fernet``
    """
    derived = hashlib.pbkdf2_hmac("sha256", key.encode(), _KDF_SALT, _KDF_ITERATIONS)
    return base64.urlsafe_b64encode(derived)


def build_cipher(keys: Sequence[str]) -> MultiFernet | None:
    """Build the cipher used for the encrypted columns.

    Args:
        keys: Raw operator-supplied keys in priority order. The first key is
            the active one and performs every encryption; all of them are
            tried, in order, when decrypting.

    Returns:
        A ``MultiFernet`` over the derived keys, or None when no keys are
        configured - which means the feature is off and values are stored as
        plaintext.

    Raises:
        KeyConfigurationError: If any key is empty or whitespace only. Such a
            key is almost certainly a misconfigured environment variable, and
            accepting it would derive a real, usable key from the empty string
            and encrypt production data under it.
    """
    # A bare str satisfies Sequence[str], so mypy would wave through a setting
    # that arrives as one comma-separated string. Iterating it would derive a
    # key per character and encrypt production data under "F".
    if isinstance(keys, str):
        raise KeyConfigurationError(
            f"{KEYS_SETTING} must be a sequence of keys, not a single string; "
            "pass a list even when there is only one key"
        )

    for position, key in enumerate(keys):
        if not key or not key.strip():
            raise KeyConfigurationError(
                f"{KEYS_SETTING}[{position}] is empty or whitespace only; "
                "remove the entry or give it a value"
            )

    if not keys:
        return None

    return MultiFernet([Fernet(_derive_fernet_key(key)) for key in keys])


def is_encrypted(value: object) -> bool:
    """Report whether a value is a stored envelope.

    Safe on any input. It runs on every load of an encrypted column, including
    rows written before the feature existed and columns holding None, so it
    answers False rather than raising for anything that is not a dict.

    Args:
        value: Any value read from, or headed for, the database

    Returns:
        True if the value is a dict carrying the envelope marker
    """
    return isinstance(value, dict) and ENVELOPE_MARKER in value


def _envelope_token(value: dict[str, Any]) -> str:
    """Extract the Fernet token from an envelope, validating its shape.

    Args:
        value: A dict for which ``is_encrypted`` is True

    Returns:
        The token, as the str that ``Fernet`` accepts

    Raises:
        DecryptionError: If the version is unrecognised or the ciphertext is
            missing or not a string. A malformed envelope is reported as a
            decryption failure rather than surfacing a KeyError or TypeError
            from deep inside a database load.
    """
    version = value.get(ENVELOPE_MARKER)
    if version != ENVELOPE_VERSION:
        raise DecryptionError(
            f"Unsupported encryption envelope version {version!r}; "
            f"this build understands version {ENVELOPE_VERSION}"
        )

    token = value.get("ciphertext")
    if not isinstance(token, str):
        raise DecryptionError(
            "Malformed encryption envelope: expected a string 'ciphertext' field, "
            f"got {type(token).__name__}"
        )
    return token


def _require_cipher(cipher: MultiFernet | None) -> MultiFernet:
    """Return the cipher, refusing to proceed without one.

    Args:
        cipher: The configured cipher, or None when encryption is disabled

    Returns:
        The cipher

    Raises:
        DecryptionError: If no cipher is configured. The value on disk is
            encrypted, so there is no plaintext to fall back to.
    """
    if cipher is None:
        raise DecryptionError(
            "This value is encrypted but no encryption key is configured; "
            f"set {KEYS_SETTING} to the key it was written with"
        )
    return cipher


def _decrypt_token(token: str, cipher: MultiFernet) -> dict[str, Any]:
    """Decrypt a token and parse the JSON it carries.

    Args:
        token: A Fernet token taken from an envelope
        cipher: The cipher to try, which tries each configured key in turn

    Returns:
        The original JSON object

    Raises:
        DecryptionError: If no configured key accepts the token, or if the
            plaintext is not a JSON object.
    """
    try:
        plaintext = cipher.decrypt(token.encode())
    except InvalidToken as e:
        raise DecryptionError(
            f"None of the configured {KEYS_SETTING} entries could decrypt this value; "
            "a key that has been rotated out may still be needed, or the stored "
            "ciphertext may be corrupt"
        ) from e

    try:
        decoded = json.loads(plaintext)
    except ValueError as e:
        raise DecryptionError(f"Decrypted value is not valid JSON: {e}") from e

    if not isinstance(decoded, dict):
        raise DecryptionError(
            f"Decrypted value is a {type(decoded).__name__}, expected a JSON object"
        )
    return decoded


def encrypt_json(value: dict[str, Any], cipher: MultiFernet) -> dict[str, Any]:
    """Encrypt a JSON object into a storable envelope.

    Args:
        value: The object to protect
        cipher: The cipher whose primary key performs the encryption

    Returns:
        A JSON-serializable envelope dict suitable for a JSONB column

    Raises:
        EncryptionError: If the value cannot be serialized to JSON.
    """
    try:
        # Sorted, separator-tight JSON keeps the plaintext deterministic, so a
        # value re-encrypted after a rotation differs only by key and nonce.
        payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        raise EncryptionError(f"Value is not JSON-serializable: {e}") from e

    token = cipher.encrypt(payload.encode())
    return {ENVELOPE_MARKER: ENVELOPE_VERSION, "ciphertext": token.decode()}


def decrypt_json(value: dict[str, Any], cipher: MultiFernet | None) -> dict[str, Any]:
    """Return the plaintext object behind a stored value.

    Args:
        value: A value loaded from the database, either an envelope or a
            legacy plaintext object
        cipher: The configured cipher, or None when encryption is disabled

    Returns:
        The plaintext object. A value that is not an envelope is returned
        unchanged and without inspection: rows written before encryption was
        enabled are the normal case during a rollout, and they are not an
        error.

    Raises:
        DecryptionError: If the value is an envelope that cannot be turned
            back into plaintext - no key configured, no key that fits, a
            version this build does not know, or a malformed envelope.
    """
    if not is_encrypted(value):
        return value

    return _decrypt_token(_envelope_token(value), _require_cipher(cipher))
