"""Move a rule's test into a list of conditions, combined by ``match``.

Revision ID: 009
Revises: 008
Create Date: 2026-11-20

Until now a rule held exactly one condition, spelled on the row itself
(``field``, ``operator``, ``value``, ``case_sensitive``). Issue #182 gives a
rule an ordered list of conditions in a new ``rule_conditions`` table, each of
which may be negated, and a ``rules.match`` of ``all`` or ``any`` saying how
they combine.

The upgrade copies each rule's flat condition into one ``rule_conditions`` row
(``order`` 0, ``negate`` false) and sets ``match`` to ``all``, then drops the
flat columns. A rule with one non-negated condition evaluates exactly as the
flat rule did, so every stored rule keeps its behaviour. The upgrade cannot
fail on existing data: every column it copies is NOT NULL on both sides.

The downgrade can. It restores the flat columns from each rule's condition,
which only describes a rule holding exactly one non-negated condition. A rule
with several conditions, or a negated one, has no flat equivalent; dropping a
condition would *broaden* the rule (a drop rule would then eat mail it used to
spare), and dropping a negation would invert it. As with 005-008, failing
loudly is deliberate: the downgrade refuses, naming how many rules are in the
way, and the operator decides what to do with them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "rules",
        sa.Column("match", sa.String(length=10), nullable=False, server_default="all"),
    )
    op.create_table(
        "rule_conditions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("rule_id", sa.Uuid(), nullable=False),
        sa.Column("order", sa.Integer(), nullable=False),
        sa.Column("field", sa.String(length=100), nullable=False),
        sa.Column("operator", sa.String(length=50), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("case_sensitive", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("negate", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(["rule_id"], ["rules.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_rule_conditions_rule_order", "rule_conditions", ["rule_id", "order"], unique=False
    )
    op.execute(
        'INSERT INTO rule_conditions (id, rule_id, "order", field, operator, value, '
        "case_sensitive, negate) "
        "SELECT gen_random_uuid(), id, 0, field, operator, value, case_sensitive, false "
        "FROM rules"
    )
    for column in ("field", "operator", "value", "case_sensitive"):
        op.drop_column("rules", column)


def downgrade() -> None:
    connection = op.get_bind()
    unrepresentable = connection.scalar(
        sa.text(
            "SELECT count(*) FROM rules r WHERE "
            "(SELECT count(*) FROM rule_conditions c WHERE c.rule_id = r.id) <> 1 "
            "OR EXISTS (SELECT 1 FROM rule_conditions c WHERE c.rule_id = r.id AND c.negate)"
        )
    )
    if unrepresentable:
        raise RuntimeError(
            f"Cannot downgrade past 009: {unrepresentable} rule(s) hold several conditions, "
            "none, or a negated one, which the single-condition schema cannot express. "
            "Rewrite or delete them first; dropping a condition would broaden the rule."
        )

    op.add_column("rules", sa.Column("field", sa.String(length=100), nullable=True))
    op.add_column("rules", sa.Column("operator", sa.String(length=50), nullable=True))
    op.add_column("rules", sa.Column("value", sa.Text(), nullable=True))
    op.add_column(
        "rules",
        sa.Column("case_sensitive", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(
        "UPDATE rules SET field = c.field, operator = c.operator, value = c.value, "
        "case_sensitive = c.case_sensitive FROM rule_conditions c WHERE c.rule_id = rules.id"
    )
    for column in ("field", "operator", "value"):
        op.alter_column("rules", column, nullable=False)

    op.drop_index("ix_rule_conditions_rule_order", table_name="rule_conditions")
    op.drop_table("rule_conditions")
    op.drop_column("rules", "match")
