"""Common Pydantic schemas."""

from pydantic import BaseModel


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    instance_id: str


class ReadyResponse(BaseModel):
    """Readiness check response."""

    status: str = "ok"
    database: str = "ok"


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str


class ErrorResponse(BaseModel):
    """Error response."""

    detail: str
