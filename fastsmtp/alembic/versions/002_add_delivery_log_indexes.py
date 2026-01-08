"""Add delivery log indexes.

Revision ID: 002
Revises: 001
Create Date: 2025-01-07

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: str | None = "001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Add indexes for delivery_log table
    op.create_index("ix_delivery_log_instance_id", "delivery_log", ["instance_id"])
    op.create_index("ix_delivery_log_delivered_at", "delivery_log", ["delivered_at"])
    op.create_index("ix_delivery_log_cleanup", "delivery_log", ["created_at", "status"])


def downgrade() -> None:
    op.drop_index("ix_delivery_log_cleanup", "delivery_log")
    op.drop_index("ix_delivery_log_delivered_at", "delivery_log")
    op.drop_index("ix_delivery_log_instance_id", "delivery_log")
