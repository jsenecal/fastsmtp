"""Settings-aware access to the at-rest encryption cipher.

``crypto`` is deliberately pure: it knows how to turn a list of key strings into a
cipher and how to encrypt a value, and nothing about where those keys come from.
This module is the seam between it and ``Settings``, so the storage layer can ask
for "the cipher this process is configured with" without importing configuration
into the cryptography itself.
"""

from functools import lru_cache

from cryptography.fernet import MultiFernet

from fastsmtp.config import get_settings
from fastsmtp.crypto import build_cipher


@lru_cache(maxsize=8)
def _cipher_for(keys: tuple[str, ...]) -> MultiFernet | None:
    """Build (and memoize) the cipher for one exact tuple of keys.

    Keyed on the keys themselves rather than cached as a singleton: deriving a
    Fernet key hashes, and a column decrypts on every row load, so this wants a
    cache -- but a cache that cannot go stale. A test or a reload that changes
    the configured keys gets a different tuple and therefore a different entry,
    with no invalidation hook to forget to call.
    """
    return build_cipher(keys)


def get_cipher() -> MultiFernet | None:
    """The cipher for the current settings, or None when no key is configured.

    ``None`` means encryption is off, which is the default and the state of every
    deployment that has not opted in. Callers must treat it as "store and read
    plaintext", not as an error: rows written before a key was configured stay
    readable either way.
    """
    return _cipher_for(tuple(get_settings().encryption_keys))
