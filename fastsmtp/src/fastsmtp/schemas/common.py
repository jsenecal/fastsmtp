"""Common Pydantic schemas."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    instance_id: str


class QueueStats(BaseModel):
    """Delivery queue statistics."""

    pending: int = 0
    failed: int = 0
    exhausted: int = 0


class ReadyResponse(BaseModel):
    """Readiness check response."""

    status: str = "ok"
    database: str = "ok"
    smtp: str | None = None  # Optional SMTP server status
    queue: QueueStats | None = None  # Optional queue statistics


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str


class ErrorResponse(BaseModel):
    """Error response."""

    detail: str
