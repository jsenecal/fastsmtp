"""RuleSet and Rule Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

# Valid field names for rules
RULE_FIELDS = {
    "from",
    "to",
    "subject",
    "body",
    "has_attachment",
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


class RuleBase(BaseModel):
    """Base rule schema."""

    field: str = Field(
        ...,
        description="Field to match: from, to, subject, body, has_attachment, "
        "dkim_result, spf_result, or header:X-Custom-Header",
    )
    operator: str = Field(
        ...,
        description="Operator: equals, contains, regex, starts_with, ends_with, exists",
    )
    value: str = Field(..., description="Value to match against")
    case_sensitive: bool = False
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

    @field_validator("field")
    @classmethod
    def validate_field(cls, v: str) -> str:
        """Validate field name."""
        if v in RULE_FIELDS:
            return v
        if v.startswith(RULE_HEADER_PREFIX):
            header_name = v[len(RULE_HEADER_PREFIX) :]
            if header_name:
                return v
            raise ValueError("Header name cannot be empty")
        valid_fields = ", ".join(sorted(RULE_FIELDS)) + f", or {RULE_HEADER_PREFIX}X-Header"
        raise ValueError(f"Invalid field '{v}'. Valid fields: {valid_fields}")

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str) -> str:
        """Validate operator."""
        if v not in RULE_OPERATORS:
            valid_ops = ", ".join(sorted(RULE_OPERATORS))
            raise ValueError(f"Invalid operator '{v}'. Valid operators: {valid_ops}")
        return v

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        """Validate action."""
        if v not in RULE_ACTIONS:
            valid_actions = ", ".join(sorted(RULE_ACTIONS))
            raise ValueError(f"Invalid action '{v}'. Valid actions: {valid_actions}")
        return v


class RuleCreate(RuleBase):
    """Schema for creating a rule."""

    pass


class RuleUpdate(BaseModel):
    """Schema for updating a rule."""

    field: str | None = None
    operator: str | None = None
    value: str | None = None
    case_sensitive: bool | None = None
    action: str | None = None
    webhook_url_override: HttpUrl | None = None
    add_tags: list[str] | None = None

    @field_validator("field")
    @classmethod
    def validate_field(cls, v: str | None) -> str | None:
        """Validate field name if provided."""
        if v is None:
            return v
        if v in RULE_FIELDS:
            return v
        if v.startswith(RULE_HEADER_PREFIX):
            header_name = v[len(RULE_HEADER_PREFIX) :]
            if header_name:
                return v
            raise ValueError("Header name cannot be empty")
        valid_fields = ", ".join(sorted(RULE_FIELDS)) + f", or {RULE_HEADER_PREFIX}X-Header"
        raise ValueError(f"Invalid field '{v}'. Valid fields: {valid_fields}")

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str | None) -> str | None:
        """Validate operator if provided."""
        if v is None:
            return v
        if v not in RULE_OPERATORS:
            valid_ops = ", ".join(sorted(RULE_OPERATORS))
            raise ValueError(f"Invalid operator '{v}'. Valid operators: {valid_ops}")
        return v

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str | None) -> str | None:
        """Validate action if provided."""
        if v is None:
            return v
        if v not in RULE_ACTIONS:
            valid_actions = ", ".join(sorted(RULE_ACTIONS))
            raise ValueError(f"Invalid action '{v}'. Valid actions: {valid_actions}")
        return v


class RuleResponse(RuleBase):
    """Schema for rule response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ruleset_id: uuid.UUID
    order: int
    created_at: datetime
    updated_at: datetime


class RuleReorderRequest(BaseModel):
    """Schema for reordering rules."""

    rule_ids: list[uuid.UUID] = Field(
        ...,
        min_length=1,
        description="Ordered list of rule IDs",
    )
