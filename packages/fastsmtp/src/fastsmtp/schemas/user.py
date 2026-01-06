"""User-related Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserBase(BaseModel):
    """Base user schema."""

    username: str = Field(..., min_length=1, max_length=255)
    email: str | None = Field(None, max_length=255)


class UserCreate(UserBase):
    """Schema for creating a user."""

    is_superuser: bool = False


class UserUpdate(BaseModel):
    """Schema for updating a user."""

    username: str | None = Field(None, min_length=1, max_length=255)
    email: str | None = None
    is_active: bool | None = None
    is_superuser: bool | None = None


class UserResponse(UserBase):
    """Schema for user response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    is_active: bool
    is_superuser: bool
    created_at: datetime
    updated_at: datetime


class UserBriefResponse(BaseModel):
    """Brief user info for nested responses."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    username: str


class APIKeyBase(BaseModel):
    """Base API key schema."""

    name: str = Field(..., min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=list)


class APIKeyCreate(APIKeyBase):
    """Schema for creating an API key."""

    expires_at: datetime | None = None


class APIKeyResponse(APIKeyBase):
    """Schema for API key response (without the actual key)."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    key_prefix: str
    expires_at: datetime | None
    last_used_at: datetime | None
    is_active: bool
    created_at: datetime


class APIKeyCreateResponse(APIKeyResponse):
    """Schema for API key creation response (includes the actual key once)."""

    key: str = Field(..., description="The full API key - only shown once")


class WhoamiResponse(BaseModel):
    """Schema for whoami response."""

    user: UserResponse
    domains: list[str] = Field(default_factory=list)
    is_root: bool = False
