"""Align the migrated schema with the models.

Revision ID: 005
Revises: 004
Create Date: 2026-08-23

Three differences between what the chain builds and what the models declare,
all dating from 001 and all invisible until tests/test_migrations.py started
diffing the two (the rest of the suite builds its schema from the models with
Base.metadata.create_all, so migrated databases were never compared):

1. Four JSONB columns were created nullable although the models declare them
   NOT NULL (``scopes``, ``webhook_headers``, ``add_tags``, ``payload``).
2. ``users.username`` and ``domains.domain_name`` got a UNIQUE constraint plus a
   separate non-unique index, where ``mapped_column(unique=True, index=True)``
   declares a single unique index. The redundant index is dropped here.
3. ``ix_recipients_domain_catchall`` was never created, so a migrated database
   accepted two catch-all recipients for the same domain - the partial unique
   index is the only thing enforcing that, because PostgreSQL lets
   ``uq_recipient_local_part`` hold any number of NULL ``local_part`` rows.

The chain has been PostgreSQL-specific since 001 (it creates ``postgresql.JSONB``
columns), so the partial index is expressed with dialect-specific WHERE clauses
exactly as the model does.

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column, value to backfill NULLs with) for columns the models declare
# non-optional - Mapped[list[str]] and Mapped[dict], never Mapped[... | None].
NOT_NULL_JSONB: tuple[tuple[str, str, str], ...] = (
    ("api_keys", "scopes", "'[]'::jsonb"),
    ("recipients", "webhook_headers", "'{}'::jsonb"),
    ("rules", "add_tags", "'[]'::jsonb"),
    ("delivery_log", "payload", "'{}'::jsonb"),
)

JSONB_TYPE = postgresql.JSONB(astext_type=sa.Text())

# Auto-generated PostgreSQL names for the inline UNIQUE constraints in 001.
UNIQUE_TO_INDEX: tuple[tuple[str, str, str, str], ...] = (
    ("users", "username", "users_username_key", "ix_users_username"),
    ("domains", "domain_name", "domains_domain_name_key", "ix_domains_domain_name"),
)


def upgrade() -> None:
    for table, column, empty in NOT_NULL_JSONB:
        op.execute(f"UPDATE {table} SET {column} = {empty} WHERE {column} IS NULL")
        op.alter_column(table, column, existing_type=JSONB_TYPE, nullable=False)

    for table, column, constraint, index in UNIQUE_TO_INDEX:
        op.drop_constraint(constraint, table, type_="unique")
        op.drop_index(index, table_name=table)
        op.create_index(index, table, [column], unique=True)

    # Fails if a domain already has two catch-all recipients. That is a data
    # error the application has always rejected; deduplicating here would delete
    # a recipient silently, so it is left to be resolved deliberately.
    op.create_index(
        "ix_recipients_domain_catchall",
        "recipients",
        ["domain_id"],
        unique=True,
        postgresql_where=sa.text("local_part IS NULL"),
        sqlite_where=sa.text("local_part IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_recipients_domain_catchall", table_name="recipients")

    for table, column, constraint, index in UNIQUE_TO_INDEX:
        op.drop_index(index, table_name=table)
        op.create_index(index, table, [column])
        op.create_unique_constraint(constraint, table, [column])

    for table, column, _empty in NOT_NULL_JSONB:
        op.alter_column(table, column, existing_type=JSONB_TYPE, nullable=True)
