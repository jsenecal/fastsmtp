"""Add soft delete columns to key models.

Revision ID: 003
Revises: 002
Create Date: 2025-01-07

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "003"
down_revision: str | None = "002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add deleted_at column to users table
    op.add_column(
        "users",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_deleted_at", "users", ["deleted_at"])

    # Add deleted_at column to api_keys table
    op.add_column(
        "api_keys",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_keys_deleted_at", "api_keys", ["deleted_at"])

    # Add deleted_at column to domains table
    op.add_column(
        "domains",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_domains_deleted_at", "domains", ["deleted_at"])

    # Add deleted_at column to recipients table
    op.add_column(
        "recipients",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_recipients_deleted_at", "recipients", ["deleted_at"])


def downgrade() -> None:
    # Remove deleted_at from recipients
    op.drop_index("ix_recipients_deleted_at", "recipients")
    op.drop_column("recipients", "deleted_at")

    # Remove deleted_at from domains
    op.drop_index("ix_domains_deleted_at", "domains")
    op.drop_column("domains", "deleted_at")

    # Remove deleted_at from api_keys
    op.drop_index("ix_api_keys_deleted_at", "api_keys")
    op.drop_column("api_keys", "deleted_at")

    # Remove deleted_at from users
    op.drop_index("ix_users_deleted_at", "users")
    op.drop_column("users", "deleted_at")
