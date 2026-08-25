"""A JSON column type that encrypts its contents at rest.

The encryption is invisible above the storage layer. A model attribute typed with
:class:`EncryptedJSON` is an ordinary ``dict`` everywhere in the application: the
API schemas, the webhook dispatcher and the CLI see exactly what they saw before.
Only the bytes in the database change.

Three properties make this safe to switch on for a database that already holds
plaintext rows:

* **Off by default.** With no key configured the type is a pass-through, which is
  byte-for-byte the behaviour of the plain JSON column it replaces.
* **Reads accept both shapes.** ``decrypt_json`` returns a non-envelope value
  unchanged, so plaintext rows written before the key existed keep working.
* **Writes convert.** Any row rewritten while a key is configured is stored
  encrypted, so the estate converts as it is touched. Rows that are never
  rewritten need the backfill command.

The column's *database* type is unchanged - still ``JSONB`` on PostgreSQL and
``JSON`` elsewhere, matching ``Base.type_annotation_map`` - because the envelope
is itself a JSON object. That is why adopting this type needs no migration.

Two consequences to know before putting this on another column:

* **The column cannot be filtered on.** Fernet output is non-deterministic, so
  once a key is configured ``where(col == {...})`` matches nothing and no JSONB
  path operator works. Nothing queries these columns today; a query added later
  would fail silently rather than loudly, so choose this type only for a column
  that is read whole and never searched.
* **Conversion follows real changes, not reads.** SQLAlchemy emits no UPDATE
  when a value is reassigned equal to what was loaded, and in-place mutation of
  the dict is not tracked at all. A legacy plaintext row is therefore converted
  only when its content genuinely changes - which is why the rollout depends on
  ``fastsmtp encrypt-existing`` rather than on traffic.
"""

from typing import Any

from sqlalchemy import JSON, Dialect
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import TypeDecorator

from fastsmtp.crypto import decrypt_json, encrypt_json
from fastsmtp.encryption import get_cipher


class EncryptedJSON(TypeDecorator[dict[str, Any]]):
    """JSON storage that encrypts the value when a key is configured."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect: Dialect) -> Any:
        """Keep the underlying type identical to the unencrypted mapping.

        ``Base.type_annotation_map`` maps ``dict`` to
        ``JSON().with_variant(JSONB(), "postgresql")``. Mirroring that exactly is
        what keeps the emitted DDL - and therefore ``compare_metadata`` in the
        migration tests - unchanged when a column adopts this type.
        """
        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())

    def process_bind_param(self, value: dict[str, Any] | None, dialect: Dialect) -> Any:
        """Encrypt on the way to the database, when there is a key to do it with."""
        if value is None:
            return None
        cipher = get_cipher()
        if cipher is None:
            return value
        return encrypt_json(value, cipher)

    def process_result_value(self, value: Any, dialect: Dialect) -> dict[str, Any] | None:
        """Decrypt on the way out, tolerating rows that were never encrypted.

        A decryption failure raises rather than degrading to ``None`` or ``{}``.
        For webhook headers a silent empty dict would post the request without its
        authentication headers, which is worse than a loud failure.
        """
        if value is None:
            return None
        return decrypt_json(value, get_cipher())
