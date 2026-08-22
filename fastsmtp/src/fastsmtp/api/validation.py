"""Shared request validation helpers for the API."""

from fastapi import HTTPException, status

from fastsmtp.config import Settings


def require_s3_for_preservation(settings: Settings) -> None:
    """Reject enabling raw message preservation when S3 is not configured.

    Domain and rule flags are stored in the database but acted on by the SMTP
    server, so without this check a flag would be accepted and then silently
    do nothing.

    Raises:
        HTTPException: 422 if the S3 settings needed for preservation are missing
    """
    missing = settings.missing_s3_settings()
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=(
                "Raw message preservation requires S3 storage to be configured. "
                f"Missing settings: {', '.join(missing)}"
            ),
        )
