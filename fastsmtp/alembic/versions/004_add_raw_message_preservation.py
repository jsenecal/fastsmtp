"""Add raw message preservation flags to domains and rules.

Revision ID: 004
Revises: 003
Create Date: 2026-08-22

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # NULL = inherit the global preserve_raw_message setting
    op.add_column(
        "domains",
        sa.Column("preserve_raw_message", sa.Boolean(), nullable=True),
    )

    # Orthogonal to Rule.action: a rule may preserve the raw message and still drop it.
    # Added with a server default so existing rows backfill, then dropped so the
    # application default is the only source of truth.
    op.add_column(
        "rules",
        sa.Column(
            "preserve_raw",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.alter_column("rules", "preserve_raw", server_default=None)


def downgrade() -> None:
    op.drop_column("rules", "preserve_raw")
    op.drop_column("domains", "preserve_raw_message")
