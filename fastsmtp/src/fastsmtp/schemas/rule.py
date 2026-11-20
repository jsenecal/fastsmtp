"""RuleSet and Rule Pydantic schemas."""

import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator, model_validator

from fastsmtp.rules.conditions import validate_regex_pattern

# Valid field names for rules
RULE_FIELDS = {
    "from",
    "to",
    "subject",
    "body",
    "has_attachment",
    "attachment_names",
    "attachment_types",
    "dkim_result",
    "spf_result",
}
RULE_HEADER_PREFIX = "header:"

# Valid operators
RULE_OPERATORS = {
    "equals",
    "contains",
    "regex",
    "starts_with",
    "ends_with",
    "exists",
}

# Valid actions
RULE_ACTIONS = {
    "forward",
    "drop",
    "tag",
    "quarantine",
}


class RuleSetBase(BaseModel):
    """Base ruleset schema."""

    name: str = Field(..., min_length=1, max_length=255)
    priority: int = Field(default=0, ge=0, le=1000)
    stop_on_match: bool = True


class RuleSetCreate(RuleSetBase):
    """Schema for creating a ruleset."""

    pass


class RuleSetUpdate(BaseModel):
    """Schema for updating a ruleset."""

    name: str | None = Field(None, min_length=1, max_length=255)
    priority: int | None = Field(None, ge=0, le=1000)
    stop_on_match: bool | None = None
    is_enabled: bool | None = None


class RuleSetResponse(RuleSetBase):
    """Schema for ruleset response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain_id: uuid.UUID
    is_enabled: bool
    created_at: datetime
    updated_at: datetime


class RuleSetWithRulesResponse(RuleSetResponse):
    """Schema for ruleset response including rules."""

    rules: list["RuleResponse"] = Field(default_factory=list)


# How a rule's conditions combine, and how many it may hold (issue #182).
RuleMatchMode = Literal["all", "any"]
MAX_RULE_CONDITIONS = 16

# The pre-#182 flat shape: one condition spelled on the rule itself. Still
# accepted on input, and echoed on output for a rule it can describe.
LEGACY_CONDITION_FIELDS = ("field", "operator", "value", "case_sensitive")

FIELD_DESCRIPTION = (
    "Field to match: from, to, subject, body, has_attachment, attachment_names, "
    "attachment_types, dkim_result, spf_result, or header:X-Custom-Header"
)
OPERATOR_DESCRIPTION = "Operator: equals, contains, regex, starts_with, ends_with, exists"
MATCH_DESCRIPTION = "all: every condition must hold; any: at least one must"


def _check_field(v: str) -> str:
    if v in RULE_FIELDS:
        return v
    if v.startswith(RULE_HEADER_PREFIX):
        if v[len(RULE_HEADER_PREFIX) :]:
            return v
        raise ValueError("Header name cannot be empty")
    valid_fields = ", ".join(sorted(RULE_FIELDS)) + f", or {RULE_HEADER_PREFIX}X-Header"
    raise ValueError(f"Invalid field '{v}'. Valid fields: {valid_fields}")


def _check_operator(v: str) -> str:
    if v not in RULE_OPERATORS:
        valid_ops = ", ".join(sorted(RULE_OPERATORS))
        raise ValueError(f"Invalid operator '{v}'. Valid operators: {valid_ops}")
    return v


def _check_action(v: str) -> str:
    if v not in RULE_ACTIONS:
        valid_actions = ", ".join(sorted(RULE_ACTIONS))
        raise ValueError(f"Invalid action '{v}'. Valid actions: {valid_actions}")
    return v


def check_condition_value(operator: str, value: str) -> None:
    """Refuse an empty value for any operator but ``exists``.

    ``value`` defaults to "" so an ``exists`` condition can omit it, but every
    other operator matches "" against everything: ``contains ""`` is true for
    any message, so a forgotten value would turn a drop rule into "drop all".
    """
    if operator != "exists" and value == "":
        raise ValueError(f"Operator '{operator}' needs a non-empty value")


def _optional(check: Callable[[str], str]) -> Callable[[str | None], str | None]:
    """Lift a validator over ``None``, for the partial-update shape."""

    def validate(v: str | None) -> str | None:
        return None if v is None else check(v)

    return validate


def _deprecated(description: str) -> Any:
    """A legacy flat field, flagged ``deprecated`` in the OpenAPI schema.

    Set through ``json_schema_extra`` rather than ``Field(deprecated=...)``:
    the latter also warns on every attribute read, and the suite turns
    DeprecationWarning into an error.
    """
    return Field(
        None,
        description=f"Deprecated, use conditions. {description}",
        json_schema_extra={"deprecated": True},
    )


class RuleConditionSchema(BaseModel):
    """One condition of a rule."""

    model_config = ConfigDict(from_attributes=True)

    field: str = Field(..., description=FIELD_DESCRIPTION)
    operator: str = Field(..., description=OPERATOR_DESCRIPTION)
    value: str = Field(default="", description="Value to match against (ignored by exists)")
    case_sensitive: bool = False
    negate: bool = Field(
        default=False,
        description="Invert the result. A field the message lacks is false, so a negated "
        "condition on it is true. A negated attachment condition is true when no part matches.",
    )

    validate_field = field_validator("field")(_check_field)
    validate_operator = field_validator("operator")(_check_operator)

    @model_validator(mode="after")
    def validate_value(self) -> "RuleConditionSchema":
        """Reject a missing value, and a regex RE2 cannot compile."""
        check_condition_value(self.operator, self.value)
        if self.operator == "regex":
            validate_regex_pattern(self.value)
        return self


RuleConditions = Annotated[
    list[RuleConditionSchema],
    Field(
        min_length=1,
        max_length=MAX_RULE_CONDITIONS,
        description=f"Conditions, evaluated in order (1 to {MAX_RULE_CONDITIONS}). "
        "On update, replaces the whole list.",
    ),
]


def _legacy_fields_sent(data: Any) -> list[str]:
    """The flat condition fields a raw request body carries; null counts as unsent."""
    if not isinstance(data, dict):
        return []
    return [name for name in LEGACY_CONDITION_FIELDS if data.get(name) is not None]


def _refuse_both_shapes(data: Any) -> None:
    if _legacy_fields_sent(data) and data.get("conditions") is not None:
        raise ValueError(
            "Send either conditions or the deprecated field/operator/value/case_sensitive, not both"
        )


class RuleActionFields(BaseModel):
    """What a rule does when it matches: everything but its conditions."""

    action: str = Field(
        default="forward",
        description="Action: forward, drop, tag, quarantine",
    )
    webhook_url_override: HttpUrl | None = Field(
        None,
        description="Override webhook URL for this rule",
    )
    add_tags: list[str] = Field(
        default_factory=list,
        description="Tags to add when rule matches",
    )
    preserve_raw: bool = Field(
        default=False,
        description="Preserve the complete raw MIME message in S3 when this rule matches. "
        "Independent of the action, so a rule can archive a message and still drop it.",
    )

    validate_action = field_validator("action")(_check_action)


class RuleCreate(RuleActionFields):
    """Schema for creating a rule.

    Takes ``match`` + ``conditions``, or the deprecated flat
    ``field``/``operator``/``value``/``case_sensitive``, which becomes a
    one-condition rule. Both at once is refused.
    """

    match: RuleMatchMode = Field(default="all", description=MATCH_DESCRIPTION)
    conditions: RuleConditions | None = None
    field: str | None = _deprecated(FIELD_DESCRIPTION)
    operator: str | None = _deprecated(OPERATOR_DESCRIPTION)
    value: str | None = _deprecated("Value to match against")
    case_sensitive: bool | None = _deprecated("Match case sensitively")

    @model_validator(mode="before")
    @classmethod
    def fold_legacy_shape(cls, data: Any) -> Any:
        """Rewrite the flat shape as a single condition, so it is validated as one."""
        _refuse_both_shapes(data)
        legacy = _legacy_fields_sent(data)
        if not legacy:
            return data
        data = dict(data)
        data["conditions"] = [{name: data.pop(name) for name in legacy}]
        return data

    @model_validator(mode="after")
    def require_conditions(self) -> "RuleCreate":
        if self.conditions is None:
            raise ValueError("A rule needs conditions (or the deprecated field/operator/value)")
        return self


class RuleUpdate(BaseModel):
    """Schema for updating a rule.

    ``conditions`` replaces the whole list. The deprecated flat fields edit the
    rule's only condition in place, and only on a rule they can describe (one
    non-negated condition); the endpoint checks that, since it needs the
    stored rule.
    """

    match: RuleMatchMode | None = Field(None, description=MATCH_DESCRIPTION)
    conditions: RuleConditions | None = None
    field: str | None = _deprecated(FIELD_DESCRIPTION)
    operator: str | None = _deprecated(OPERATOR_DESCRIPTION)
    value: str | None = _deprecated("Value to match against")
    case_sensitive: bool | None = _deprecated("Match case sensitively")
    action: str | None = None
    webhook_url_override: HttpUrl | None = None
    add_tags: list[str] | None = None
    preserve_raw: bool | None = None

    validate_field = field_validator("field")(_optional(_check_field))
    validate_operator = field_validator("operator")(_optional(_check_operator))
    validate_action = field_validator("action")(_optional(_check_action))

    @model_validator(mode="before")
    @classmethod
    def refuse_both_shapes(cls, data: Any) -> Any:
        _refuse_both_shapes(data)
        return data

    @model_validator(mode="after")
    def validate_regex_value(self) -> "RuleUpdate":
        """Reject a flat regex update whose pattern RE2 cannot compile.

        Only covers payloads carrying both operator and value; a partial
        update is checked against the stored condition by the update endpoint.
        """
        if self.operator == "regex" and self.value is not None:
            validate_regex_pattern(self.value)
        return self


class _Negatable(Protocol):
    @property
    def negate(self) -> bool: ...


def legacy_condition[C: _Negatable](conditions: Sequence[C]) -> C | None:
    """The condition the flat fields can stand for, or ``None`` if there is none.

    That is the rule's only condition, provided it is not negated: the flat
    shape has no way to say NOT, so echoing (or editing) a negated condition
    through it would describe the opposite rule.
    """
    if len(conditions) == 1 and not conditions[0].negate:
        return conditions[0]
    return None


class RuleResponse(RuleActionFields):
    """Schema for rule response.

    ``conditions`` and ``match`` are always present. The deprecated flat
    fields echo the condition of a rule holding exactly one non-negated
    condition, so pre-#182 clients keep reading it; for any other rule they
    are null, because they cannot describe it.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ruleset_id: uuid.UUID
    order: int
    match: RuleMatchMode
    conditions: list[RuleConditionSchema]
    field: str | None = _deprecated(FIELD_DESCRIPTION)
    operator: str | None = _deprecated(OPERATOR_DESCRIPTION)
    value: str | None = _deprecated("Value to match against")
    case_sensitive: bool | None = _deprecated("Match case sensitively")
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def echo_legacy_fields(self) -> "RuleResponse":
        legacy = legacy_condition(self.conditions)
        if legacy is not None:
            for name in LEGACY_CONDITION_FIELDS:
                setattr(self, name, getattr(legacy, name))
        return self


class RuleReorderRequest(BaseModel):
    """Schema for reordering rules."""

    rule_ids: list[uuid.UUID] = Field(
        ...,
        min_length=1,
        description="Ordered list of rule IDs",
    )
