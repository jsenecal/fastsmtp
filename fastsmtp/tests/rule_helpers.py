"""Builders for rules in tests.

A rule's test lives in its ``conditions`` (issue #182), so a test that only
cares about one condition would otherwise spell out a ``RuleCondition`` list
every time. ``make_rule`` keeps the old one-line shape for that common case.
``mime_helpers.py`` next door is the same shape.
"""

from typing import Any

from fastsmtp.db.models import Rule, RuleCondition


def make_condition(
    field: str,
    operator: str,
    value: str = "",
    case_sensitive: bool = False,
    negate: bool = False,
    order: int = 0,
) -> RuleCondition:
    """A condition row, unattached."""
    return RuleCondition(
        order=order,
        field=field,
        operator=operator,
        value=value,
        case_sensitive=case_sensitive,
        negate=negate,
    )


def make_rule(
    field: str,
    operator: str,
    value: str = "",
    case_sensitive: bool = False,
    negate: bool = False,
    **kwargs: Any,
) -> Rule:
    """A rule holding exactly one condition; ``kwargs`` go to ``Rule``."""
    kwargs.setdefault("match", "all")
    return Rule(
        conditions=[make_condition(field, operator, value, case_sensitive, negate)],
        **kwargs,
    )


def make_compound_rule(match: str, conditions: list[tuple[Any, ...]], **kwargs: Any) -> Rule:
    """A rule over several conditions, each a ``make_condition`` argument tuple."""
    return Rule(
        match=match,
        conditions=[
            make_condition(*condition, order=index) for index, condition in enumerate(conditions)
        ],
        **kwargs,
    )
