"""Initial schema.

Revision ID: 001
Revises:
Create Date: 2025-01-07

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Users table
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_superuser", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("username"),
    )
    op.create_index("ix_users_username", "users", ["username"])

    # API Keys table
    op.create_table(
        "api_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("key_hash", sa.String(255), nullable=False),
        sa.Column("key_salt", sa.String(128), nullable=True),
        sa.Column("key_prefix", sa.String(20), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scopes", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("ix_api_keys_key_hash", "api_keys", ["key_hash"])

    # Domains table
    op.create_table(
        "domains",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("domain_name", sa.String(255), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("verify_dkim", sa.Boolean(), nullable=True),
        sa.Column("verify_spf", sa.Boolean(), nullable=True),
        sa.Column("reject_dkim_fail", sa.Boolean(), nullable=True),
        sa.Column("reject_spf_fail", sa.Boolean(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_name"),
    )
    op.create_index("ix_domains_domain_name", "domains", ["domain_name"])

    # Domain Members table
    op.create_table(
        "domain_members",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default=sa.text("'member'")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "domain_id", name="uq_domain_member"),
    )
    op.create_index("ix_domain_members_user_domain", "domain_members", ["user_id", "domain_id"])

    # Recipients table
    op.create_table(
        "recipients",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=False),
        sa.Column("local_part", sa.String(255), nullable=True),
        sa.Column("webhook_url", sa.Text(), nullable=False),
        sa.Column("webhook_headers", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id", "local_part", name="uq_recipient_local_part"),
    )
    op.create_index("ix_recipients_domain_id", "recipients", ["domain_id"])
    op.create_index("ix_recipients_domain_local", "recipients", ["domain_id", "local_part"])

    # RuleSets table
    op.create_table(
        "rulesets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("stop_on_match", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain_id", "name", name="uq_ruleset_name"),
    )
    op.create_index("ix_rulesets_domain_id", "rulesets", ["domain_id"])
    op.create_index("ix_rulesets_domain_priority", "rulesets", ["domain_id", "priority"])

    # Rules table
    op.create_table(
        "rules",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ruleset_id", sa.Uuid(), nullable=False),
        sa.Column("order", sa.Integer(), nullable=False),
        sa.Column("field", sa.String(100), nullable=False),
        sa.Column("operator", sa.String(50), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("case_sensitive", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("action", sa.String(50), nullable=False, server_default=sa.text("'forward'")),
        sa.Column("webhook_url_override", sa.Text(), nullable=True),
        sa.Column("add_tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["ruleset_id"], ["rulesets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_rules_ruleset_id", "rules", ["ruleset_id"])
    op.create_index("ix_rules_ruleset_order", "rules", ["ruleset_id", "order"])

    # Delivery Log table
    op.create_table(
        "delivery_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("domain_id", sa.Uuid(), nullable=True),
        sa.Column("message_id", sa.String(255), nullable=False),
        sa.Column("recipient_id", sa.Uuid(), nullable=True),
        sa.Column("webhook_url", sa.Text(), nullable=False),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(50), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("last_status_code", sa.Integer(), nullable=True),
        sa.Column("instance_id", sa.String(50), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("dkim_result", sa.String(50), nullable=True),
        sa.Column("spf_result", sa.String(50), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["domain_id"], ["domains.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["recipient_id"], ["recipients.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_delivery_log_domain_id", "delivery_log", ["domain_id"])
    op.create_index("ix_delivery_log_message_id", "delivery_log", ["message_id"])
    op.create_index("ix_delivery_log_status", "delivery_log", ["status"])
    op.create_index("ix_delivery_log_next_retry_at", "delivery_log", ["next_retry_at"])
    op.create_index("ix_delivery_log_status_retry", "delivery_log", ["status", "next_retry_at"])
    op.create_index("ix_delivery_log_domain_created", "delivery_log", ["domain_id", "created_at"])


def downgrade() -> None:
    # Drop tables in reverse order (respecting foreign key dependencies)
    op.drop_table("delivery_log")
    op.drop_table("rules")
    op.drop_table("rulesets")
    op.drop_table("recipients")
    op.drop_table("domain_members")
    op.drop_table("domains")
    op.drop_table("api_keys")
    op.drop_table("users")
