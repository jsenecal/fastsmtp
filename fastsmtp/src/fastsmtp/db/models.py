"""SQLAlchemy database models."""

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

if TYPE_CHECKING:
    pass


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


class User(Base, TimestampMixin):
    """User account model."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
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

    def __repr__(self) -> str:
        return f"<User {self.username}>"


class APIKey(Base, TimestampMixin):
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
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    user: Mapped["User"] = relationship(back_populates="api_keys")

    def __repr__(self) -> str:
        return f"<APIKey {self.key_prefix}...>"


class Domain(Base, TimestampMixin):
    """Email domain configuration."""

    __tablename__ = "domains"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    domain_name: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )
    is_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)
    verify_dkim: Mapped[bool | None] = mapped_column(nullable=True)
    verify_spf: Mapped[bool | None] = mapped_column(nullable=True)
    reject_dkim_fail: Mapped[bool | None] = mapped_column(nullable=True)
    reject_spf_fail: Mapped[bool | None] = mapped_column(nullable=True)

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


class Recipient(Base, TimestampMixin):
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
    local_part: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # NULL = catch-all
    webhook_url: Mapped[str] = mapped_column(Text, nullable=False)
    webhook_headers: Mapped[dict] = mapped_column(default=dict)
    is_enabled: Mapped[bool] = mapped_column(default=True, nullable=False)

    # Relationships
    domain: Mapped["Domain"] = relationship(back_populates="recipients")

    __table_args__ = (
        UniqueConstraint("domain_id", "local_part", name="uq_recipient_local_part"),
        Index("ix_recipients_domain_local", "domain_id", "local_part"),
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
    webhook_url: Mapped[str] = mapped_column(Text, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # pending, delivered, failed, exhausted
    attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    next_retry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(nullable=True)
    instance_id: Mapped[str] = mapped_column(String(50), nullable=False)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[dict] = mapped_column(default=dict)
    dkim_result: Mapped[str | None] = mapped_column(String(50), nullable=True)
    spf_result: Mapped[str | None] = mapped_column(String(50), nullable=True)

    __table_args__ = (
        Index("ix_delivery_log_status_retry", "status", "next_retry_at"),
        Index("ix_delivery_log_domain_created", "domain_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<DeliveryLog {self.message_id} status={self.status}>"
