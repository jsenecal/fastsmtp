"""Exclude soft-deleted recipients from the catch-all unique index.

Revision ID: 006
Revises: 005
Create Date: 2026-08-23

``ix_recipients_domain_catchall`` guarantees at most one catch-all recipient
per domain, but its predicate (``local_part IS NULL``) also counted
soft-deleted rows. ``Recipient`` uses ``SoftDeleteMixin``, so a deleted
catch-all stays in the table with ``deleted_at`` set - and kept blocking the
creation of its replacement, turning the routine delete-then-recreate admin
operation into a unique violation. The predicate now also requires
``deleted_at IS NULL``, matching the model.

The upgrade cannot fail on existing data: every set of rows that satisfied the
old, broader predicate satisfies the narrower one. The downgrade can - a live
catch-all plus a tombstoned one for the same domain is valid under this
revision but violates the old index. As with 005, failing loudly is deliberate;
deduplicating here would silently delete a recipient.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_index("ix_recipients_domain_catchall", table_name="recipients")
    op.create_index(
        "ix_recipients_domain_catchall",
        "recipients",
        ["domain_id"],
        unique=True,
        postgresql_where=sa.text("local_part IS NULL AND deleted_at IS NULL"),
        sqlite_where=sa.text("local_part IS NULL AND deleted_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_recipients_domain_catchall", table_name="recipients")
    op.create_index(
        "ix_recipients_domain_catchall",
        "recipients",
        ["domain_id"],
        unique=True,
        postgresql_where=sa.text("local_part IS NULL"),
        sqlite_where=sa.text("local_part IS NULL"),
    )
