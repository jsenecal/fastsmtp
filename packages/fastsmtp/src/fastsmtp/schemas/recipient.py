"""Recipient-related Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class RecipientBase(BaseModel):
    """Base recipient schema."""

    local_part: str | None = Field(
        None,
        max_length=255,
        description="Local part of email address (before @). None for catch-all.",
    )
    webhook_url: HttpUrl = Field(..., description="URL to forward emails to")
    webhook_headers: dict[str, str] = Field(
        default_factory=dict,
        description="Additional headers to send with webhook requests",
    )


class RecipientCreate(RecipientBase):
    """Schema for creating a recipient."""

    pass


class RecipientUpdate(BaseModel):
    """Schema for updating a recipient."""

    local_part: str | None = None
    webhook_url: HttpUrl | None = None
    webhook_headers: dict[str, str] | None = None
    is_enabled: bool | None = None


class RecipientResponse(BaseModel):
    """Schema for recipient response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain_id: uuid.UUID
    local_part: str | None
    webhook_url: str
    webhook_headers: dict[str, str]
    is_enabled: bool
    created_at: datetime
    updated_at: datetime

    @property
    def email_pattern(self) -> str:
        """Return the email pattern this recipient matches."""
        return f"{self.local_part or '*'}@..."
