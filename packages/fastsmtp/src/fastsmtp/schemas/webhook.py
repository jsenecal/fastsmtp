"""Webhook and DeliveryLog Pydantic schemas."""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class DeliveryLogResponse(BaseModel):
    """Schema for delivery log response."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain_id: uuid.UUID | None
    message_id: str
    recipient_id: uuid.UUID | None
    webhook_url: str
    payload_hash: str
    status: str
    attempts: int
    next_retry_at: datetime | None
    last_error: str | None
    last_status_code: int | None
    instance_id: str
    delivered_at: datetime | None
    dkim_result: str | None
    spf_result: str | None
    created_at: datetime
    updated_at: datetime


class DeliveryLogDetailResponse(DeliveryLogResponse):
    """Schema for delivery log response with payload."""

    payload: dict


class DeliveryLogFilter(BaseModel):
    """Schema for filtering delivery logs."""

    status: str | None = Field(None, description="Filter by status")
    since: datetime | None = Field(None, description="Filter since datetime")
    until: datetime | None = Field(None, description="Filter until datetime")
    message_id: str | None = Field(None, description="Filter by message ID")
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class TestWebhookRequest(BaseModel):
    """Schema for testing a webhook."""

    webhook_url: HttpUrl
    subject: str = "Test email from FastSMTP"
    from_address: str = "test@fastsmtp.local"
    to_address: str = "recipient@example.com"
    body: str = "This is a test email sent by FastSMTP to verify webhook connectivity."


class TestWebhookResponse(BaseModel):
    """Schema for test webhook response."""

    success: bool
    status_code: int | None = None
    error: str | None = None
    response_time_ms: float | None = None
