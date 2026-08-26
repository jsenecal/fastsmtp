"""SQLAlchemy database models."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    ColumnElement,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from fastsmtp.db.encrypted_types import EncryptedJSON

if TYPE_CHECKING:
    pass


def _live_unique_index(name: str, *columns: str) -> Index:
    """Partial unique index over live rows: at most one *live* row per key.

    Tombstones are excluded so a soft-deleted row never blocks re-creating
    the same key - a username, a domain name, a (domain, local_part) pair.
    Written as an Index rather than a UniqueConstraint, which cannot take a
    predicate. Index names are kept from the constraints they replaced so
    error messages and references stay stable (migrations 007 and 008).
    """
    return Index(
        name,
        *columns,
        unique=True,
        postgresql_where=text("deleted_at IS NULL"),
        sqlite_where=text("deleted_at IS NULL"),
    )


class Base(DeclarativeBase):
    """Base class for all models."""

    # Use JSON with JSONB variant for PostgreSQL (works on SQLite too)
    type_annotation_map = {
        dict: JSON().with_variant(JSONB(), "postgresql"),
        list[str]: JSON().with_variant(JSONB(), "postgresql"),
        uuid.UUID: Uuid,
    }


class TimestampMixin:
    """Mixin for created_at and updated_at timestamps."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """Mixin for soft delete support.

    Adds a deleted_at timestamp field. When set, the record is considered
    soft deleted and can be filtered out of normal queries while preserving
    audit history.
    """

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        default=None,
        nullable=True,
        index=True,
    )

    @property
    def is_deleted(self) -> bool:
        """Check if this record has been soft deleted."""
        return self.deleted_at is not None

    @classmethod
    def live(cls) -> ColumnElement[bool]:
        """Filter for rows that are not tombstoned.

        The only place ``deleted_at IS NULL`` is spelled: every read path
        filters through this so a grep for the primitive audits them all.
        """
        return cls.deleted_at.is_(None)


class User(Base, TimestampMixin, SoftDeleteMixin):
    """User account model."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_superuser: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    api_keys: Mapped[list["APIKey"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
    domain_memberships: Mapped[list["DomainMember"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    __table_args__ = (_live_unique_index("ix_users_username", "username"),)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class APIKey(Base, TimestampMixin, SoftDeleteMixin):
    """API key for authentication."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    key_salt: Mapped[str | None] = mapped_column(
        String(128), nullable=True
    )  # Hex-encoded salt for PBKDF2. NULL = legacy unsalted key
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="api_keys")

    @property
    def is_salted(self) -> bool:
        """Check if this key uses salted hashing."""
        return self.key_salt is not None

    def __repr__(self) -> str:
        return f"<APIKey {self.key_prefix}...>"


class Domain(Base, TimestampMixin, SoftDeleteMixin):
    """Email domain configuration."""

    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    domain_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    verify_dkim: Mapped[bool | None] = mapped_column(nullable=True)
    verify_spf: Mapped[bool | None] = mapped_column(nullable=True)
    reject_dkim_fail: Mapped[bool | None] = mapped_column(nullable=True)
    reject_spf_fail: Mapped[bool | None] = mapped_column(nullable=True)
    # NULL = inherit the global preserve_raw_message setting
    preserve_raw_message: Mapped[bool | None] = mapped_column(nullable=True)

    # Relationships
    members: Mapped[list["DomainMember"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
    )
    recipients: Mapped[list["Recipient"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
    )
    rulesets: Mapped[list["RuleSet"]] = relationship(
        back_populates="domain",
        cascade="all, delete-orphan",
    )

    __table_args__ = (_live_unique_index("ix_domains_domain_name", "domain_name"),)

    def __repr__(self) -> str:
        return f"<Domain {self.domain_name}>"


class DomainMember(Base, TimestampMixin):
    """Association between users and domains with roles."""

    __tablename__ = "domain_members"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(
        String(50), default="member", nullable=False
    )  # owner, admin, member

    # Relationships
    user: Mapped["User"] = relationship(back_populates="domain_memberships")
    domain: Mapped["Domain"] = relationship(back_populates="members")

    __table_args__ = (
        UniqueConstraint("user_id", "domain_id", name="uq_domain_member"),
        Index("ix_domain_members_user_domain", "user_id", "domain_id"),
    )

    def __repr__(self) -> str:
        return f"<DomainMember user={self.user_id} domain={self.domain_id} role={self.role}>"


class Recipient(Base, TimestampMixin, SoftDeleteMixin):
    """Email recipient configuration with webhook mapping."""

    __tablename__ = "recipients"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    local_part: Mapped[str | None] = mapped_column(String(255), nullable=True)  # NULL = catch-all
    webhook_url: Mapped[str] = mapped_column(Text, nullable=False)
    # Encrypted at rest when a key is configured: these are the customer's own
    # credentials for their endpoint. See db/encrypted_types.py; the stored type
    # is unchanged, so this needs no migration.
    webhook_headers: Mapped[dict] = mapped_column(EncryptedJSON, default=dict)
    is_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    domain: Mapped["Domain"] = relationship(back_populates="recipients")

    __table_args__ = (
        # At most one *live* recipient per (domain, local_part). NULL
        # local_part rows never conflict here (SQL NULL semantics); the
        # catch-all case is owned by ix_recipients_domain_catchall below.
        _live_unique_index("uq_recipient_local_part", "domain_id", "local_part"),
        Index("ix_recipients_domain_local", "domain_id", "local_part"),
        # Partial unique index to prevent multiple catch-all recipients per domain
        # PostgreSQL allows multiple NULLs in unique constraints, so we need this
        # Use text() and dialect-specific where clauses for cross-database support
        # Soft-deleted rows are excluded: a tombstoned catch-all must not block
        # creating its replacement.
        Index(
            "ix_recipients_domain_catchall",
            "domain_id",
            unique=True,
            postgresql_where=text("local_part IS NULL AND deleted_at IS NULL"),
            sqlite_where=text("local_part IS NULL AND deleted_at IS NULL"),
        ),
    )

    def __repr__(self) -> str:
        local = self.local_part or "*"
        return f"<Recipient {local}@{self.domain_id}>"


class RuleSet(Base, TimestampMixin):
    """Collection of rules for a domain."""

    __tablename__ = "rulesets"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    domain_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("domains.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[int] = mapped_column(default=0, nullable=False)
    stop_on_match: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    domain: Mapped["Domain"] = relationship(back_populates="rulesets")
    rules: Mapped[list["Rule"]] = relationship(
        back_populates="ruleset",
        cascade="all, delete-orphan",
        order_by="Rule.order",
    )

    __table_args__ = (
        UniqueConstraint("domain_id", "name", name="uq_ruleset_name"),
        Index("ix_rulesets_domain_priority", "domain_id", "priority"),
    )

    def __repr__(self) -> str:
        return f"<RuleSet {self.name}>"


class Rule(Base, TimestampMixin):
    """Individual rule within a ruleset."""

    __tablename__ = "rules"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    ruleset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("rulesets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    order: Mapped[int] = mapped_column(nullable=False)
    field: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # from, to, subject, header:X-Custom, body, has_attachment, dkim_result, spf_result
    operator: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # equals, contains, regex, starts_with, ends_with, exists
    value: Mapped[str] = mapped_column(Text, nullable=False)
    case_sensitive: Mapped[bool] = mapped_column(default=False, nullable=False)
    action: Mapped[str] = mapped_column(
        String(50), default="forward", nullable=False
    )  # forward, drop, tag, quarantine
    webhook_url_override: Mapped[str | None] = mapped_column(Text, nullable=True)
    add_tags: Mapped[list[str]] = mapped_column(default=list)
    # Orthogonal to action: a rule may preserve the raw message and still drop it
    preserve_raw: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    ruleset: Mapped["RuleSet"] = relationship(back_populates="rules")

    __table_args__ = (Index("ix_rules_ruleset_order", "ruleset_id", "order"),)

    def __repr__(self) -> str:
        return f"<Rule {self.field} {self.operator} '{self.value[:20]}...'>"


class DeliveryLog(Base, TimestampMixin):
    """Log of webhook delivery attempts."""

    __tablename__ = "delivery_log"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    domain_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("domains.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    message_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    recipient_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("recipients.id", ondelete="SET NULL"),
        nullable=True,
    )
    # Relationship for eager loading (used by webhook worker to get headers).
    # lazy="raise" so an unloaded access fails loudly instead of silently
    # evaluating to None and stripping the recipient's auth headers.
    recipient: Mapped["Recipient | None"] = relationship(
        "Recipient",
        foreign_keys=[recipient_id],
        lazy="raise",
    )
    webhook_url: Mapped[str] = mapped_column(Text, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # pending, delivered, failed, exhausted, cancelled
    attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(nullable=True)
    instance_id: Mapped[str] = mapped_column(String(50), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Encrypted at rest when a key is configured: this holds the whole webhook
    # payload, which is the message - subject, bodies, and inline attachments -
    # kept for the retention window. See db/encrypted_types.py; the stored type
    # is unchanged, so this needs no migration.
    #
    # ``payload_hash`` above stays a hash of the *plaintext*: it is computed in
    # ``webhook/queue.py`` before the row is flushed, and the column type only
    # encrypts on the way to the database. Hashing the ciphertext would make it
    # useless as a content fingerprint, since Fernet output differs every time.
    payload: Mapped[dict] = mapped_column(EncryptedJSON, default=dict)
    dkim_result: Mapped[str | None] = mapped_column(String(50), nullable=True)
    spf_result: Mapped[str | None] = mapped_column(String(50), nullable=True)

    __table_args__ = (
        Index("ix_delivery_log_status_retry", "status", "next_retry_at"),
        Index("ix_delivery_log_domain_created", "domain_id", "created_at"),
        Index("ix_delivery_log_instance_id", "instance_id"),
        Index("ix_delivery_log_delivered_at", "delivered_at"),
        # Named for the cleanup job, but load-bearing for startup too: the
        # encryption guard samples the newest rows by created_at, and this is
        # the index that keeps that an index scan instead of a sort over the
        # whole table (db/encryption_guard.py). Do not drop or reorder its
        # columns on cleanup's behalf alone.
        Index("ix_delivery_log_cleanup", "created_at", "status"),
    )

    def __repr__(self) -> str:
        return f"<DeliveryLog {self.message_id} status={self.status}>"
