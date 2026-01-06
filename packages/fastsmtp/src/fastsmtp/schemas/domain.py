"""Domain-related Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class DomainBase(BaseModel):
    """Base domain schema."""

    domain_name: str = Field(..., min_length=1, max_length=255)


class DomainCreate(DomainBase):
    """Schema for creating a domain."""

    verify_dkim: bool | None = None
    verify_spf: bool | None = None
    reject_dkim_fail: bool | None = None
    reject_spf_fail: bool | None = None


class DomainUpdate(BaseModel):
    """Schema for updating a domain."""

    is_enabled: bool | None = None
    verify_dkim: bool | None = None
    verify_spf: bool | None = None
    reject_dkim_fail: bool | None = None
    reject_spf_fail: bool | None = None


class DomainResponse(DomainBase):
    """Schema for domain response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_enabled: bool
    verify_dkim: bool | None
    verify_spf: bool | None
    reject_dkim_fail: bool | None
    reject_spf_fail: bool | None
    created_at: datetime
    updated_at: datetime


class DomainBriefResponse(BaseModel):
    """Brief domain info for nested responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain_name: str
    is_enabled: bool


class MemberBase(BaseModel):
    """Base member schema."""

    role: str = Field(default="member", pattern="^(owner|admin|member)$")


class MemberCreate(MemberBase):
    """Schema for adding a member to a domain."""

    user_id: uuid.UUID


class MemberUpdate(BaseModel):
    """Schema for updating a member's role."""

    role: str = Field(..., pattern="^(owner|admin|member)$")


class MemberResponse(MemberBase):
    """Schema for member response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    domain_id: uuid.UUID
    username: str | None = None
    created_at: datetime
    updated_at: datetime
