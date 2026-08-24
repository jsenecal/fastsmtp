"""Exclude soft-deleted users and domains from the name uniqueness rules.

Revision ID: 008
Revises: 007
Create Date: 2026-08-24

The same defect class as 006 and 007, two tables over. ``ix_users_username``
and ``ix_domains_domain_name`` (unique indexes since 005) guarantee at most one
user per username and one domain per name, but they also count soft-deleted
rows. ``User`` and ``Domain`` use ``SoftDeleteMixin``, and with v0.5.0 the API
and CLI soft-delete them, so a deleted account or domain would stay in the
table with ``deleted_at`` set - and keep blocking the recreation of its name,
turning the routine delete-then-recreate admin operation into a unique
violation. Both indexes are rebuilt as partial unique indexes over the same
column, restricted to ``deleted_at IS NULL`` and keeping the same names so
error messages and existing references stay stable.

Index changes only: no data is rewritten. The upgrade cannot fail on existing
data - every set of rows that satisfied the old index satisfies the strictly
narrower one. The downgrade can: a live row plus a tombstoned one sharing a
name is valid under this revision but violates the old index. As with 005,
006 and 007, failing loudly is deliberate; deduplicating here would silently
delete a user or a domain.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "008"
down_revision: str | None = "007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column, index) for the two unique name indexes 005 created.
NAME_INDEXES: tuple[tuple[str, str, str], ...] = (
    ("users", "username", "ix_users_username"),
    ("domains", "domain_name", "ix_domains_domain_name"),
)


def upgrade() -> None:
    for table, column, index in NAME_INDEXES:
        op.drop_index(index, table_name=table)
        op.create_index(
            index,
            table,
            [column],
            unique=True,
            postgresql_where=sa.text("deleted_at IS NULL"),
            sqlite_where=sa.text("deleted_at IS NULL"),
        )


def downgrade() -> None:
    # Fails if a live row and a tombstone share a name. Deliberate (005/006/007
    # stance): deduplicating would silently delete a user or a domain.
    for table, column, index in NAME_INDEXES:
        op.drop_index(index, table_name=table)
        op.create_index(index, table, [column], unique=True)
