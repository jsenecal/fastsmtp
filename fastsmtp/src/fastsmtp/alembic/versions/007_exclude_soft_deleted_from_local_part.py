"""Exclude soft-deleted recipients from the named local-part uniqueness rule.

Revision ID: 007
Revises: 006
Create Date: 2026-08-23

The same defect class as 006, one constraint over. ``uq_recipient_local_part``
guarantees at most one recipient per (domain, local_part), but as a plain
UNIQUE constraint it also counted soft-deleted rows. ``Recipient`` uses
``SoftDeleteMixin``, so a deleted named recipient stays in the table with
``deleted_at`` set - and kept blocking the recreation of the same local part,
turning the routine delete-then-recreate admin operation into a unique
violation. A UNIQUE constraint cannot take a predicate, so the constraint is
replaced by a partial unique index over the same columns, restricted to
``deleted_at IS NULL`` and keeping the same name so error messages and
existing references stay stable.

NULL ``local_part`` rows (catch-alls) never conflicted under either form -
SQL NULL semantics - and stay owned by ``ix_recipients_domain_catchall``
from 006.

The upgrade cannot fail on existing data: every set of rows that satisfied the
old constraint satisfies the strictly narrower index. The downgrade can - a
live named recipient plus a tombstoned one with the same local part is valid
under this revision but violates the old constraint. As with 005 and 006,
failing loudly is deliberate; deduplicating here would silently delete a
recipient.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint("uq_recipient_local_part", "recipients", type_="unique")
    op.create_index(
        "uq_recipient_local_part",
        "recipients",
        ["domain_id", "local_part"],
        unique=True,
        postgresql_where=sa.text("deleted_at IS NULL"),
        sqlite_where=sa.text("deleted_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_recipient_local_part", table_name="recipients")
    op.create_unique_constraint(
        "uq_recipient_local_part", "recipients", ["domain_id", "local_part"]
    )
