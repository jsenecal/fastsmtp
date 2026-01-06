"""RuleSet and Rule Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl

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


class RuleResponse(RuleBase):
    """Schema for rule response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ruleset_id: uuid.UUID
    order: int
    webhook_url_override: str | None = None
    created_at: datetime
    updated_at: datetime


class RuleReorderRequest(BaseModel):
    """Schema for reordering rules."""

    rule_ids: list[uuid.UUID] = Field(
        ...,
        min_length=1,
        description="Ordered list of rule IDs",
    )
