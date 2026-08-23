"""S3-compatible storage for email attachments."""

import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from aiobotocore.session import get_session

if TYPE_CHECKING:
    from fastsmtp.config import Settings

logger = logging.getLogger(__name__)


@dataclass
class S3AttachmentInfo:
    """Information about an attachment stored in S3."""

    bucket: str
    key: str
    url: str
    presigned_url: str | None = None


@dataclass
class S3RawMessageInfo:
    """Information about a raw MIME message preserved in S3."""

    bucket: str
    key: str
    url: str
    size: int
    presigned_url: str | None = None


class S3ConfigurationError(Exception):
    """Raised when S3 storage is asked for without bucket or credentials."""


class S3UploadError(Exception):
    """Raised when S3 upload fails."""

    def __init__(self, message: str, filename: str, cause: Exception | None = None):
        self.filename = filename
        self.cause = cause
        super().__init__(message)


def sanitize_key_component(value: str) -> str:
    """Sanitize a string for use in S3 key.

    Removes characters that are problematic in S3 keys.
    """
    # Remove < > and other problematic characters
    sanitized = re.sub(r"[<>\"'\\|?*\x00-\x1f]", "", value)
    # Replace spaces and other whitespace with underscores
    sanitized = re.sub(r"\s+", "_", sanitized)
    # Collapse multiple underscores
    sanitized = re.sub(r"_+", "_", sanitized)
    # Remove leading/trailing underscores
    sanitized = sanitized.strip("_")
    return sanitized or "unnamed"


class S3Storage:
    """Async S3 storage client for attachments."""

    def __init__(self, settings: "Settings"):
        """Bind to settings that actually carry a bucket and credentials.

        ``validate_s3_config`` only guards the globally-enabled features; raw
        preservation is also switched on per domain and per rule in the
        database, so a row can request S3 on a process configured without it.
        Resolving the three required values here means the rest of the class --
        and mypy -- can treat them as present.
        """
        bucket = settings.s3_bucket
        access_key = settings.s3_access_key
        secret_key = settings.s3_secret_key
        if not (bucket and access_key and secret_key):
            raise S3ConfigurationError(
                f"S3 storage requires: {', '.join(settings.missing_s3_settings())}"
            )

        self.settings = settings
        self.bucket = bucket
        self._access_key = access_key
        self._secret_key = secret_key
        self._session = get_session()

    def _build_key(self, domain: str, message_id: str, filename: str) -> str:
        """Build S3 key for attachment."""
        safe_message_id = sanitize_key_component(message_id)
        safe_filename = sanitize_key_component(filename)
        prefix = self.settings.s3_prefix.strip("/")
        return f"{prefix}/{domain}/{safe_message_id}/{safe_filename}"

    def _build_raw_key(
        self,
        domain: str,
        message_id: str,
        received_at: datetime | None = None,
    ) -> str:
        """Build S3 key for a preserved raw message.

        Keys are partitioned by receive date so archives stay listable and
        S3 lifecycle rules can expire them by age.
        """
        received_at = received_at or datetime.now(UTC)
        safe_message_id = sanitize_key_component(message_id)
        prefix = self.settings.s3_raw_prefix.strip("/")
        date_path = received_at.strftime("%Y/%m/%d")
        return f"{prefix}/{domain}/{date_path}/{safe_message_id}.eml"

    def _build_url(self, key: str) -> str:
        """Build public URL for S3 object."""
        bucket = self.bucket
        if self.settings.s3_endpoint_url:
            endpoint = self.settings.s3_endpoint_url.rstrip("/")
            return f"{endpoint}/{bucket}/{key}"
        else:
            region = self.settings.s3_region
            return f"https://s3.{region}.amazonaws.com/{bucket}/{key}"

    def _client_kwargs(self) -> dict[str, Any]:
        """Build keyword arguments for creating the S3 client."""
        kwargs: dict[str, Any] = {
            "aws_access_key_id": self._access_key.get_secret_value(),
            "aws_secret_access_key": self._secret_key.get_secret_value(),
            "region_name": self.settings.s3_region,
        }
        if self.settings.s3_endpoint_url:
            kwargs["endpoint_url"] = self.settings.s3_endpoint_url
        return kwargs

    async def upload_attachment(
        self,
        content: bytes,
        domain: str,
        message_id: str,
        filename: str,
        content_type: str,
    ) -> S3AttachmentInfo:
        """Upload attachment to S3.

        Args:
            content: File content as bytes
            domain: Email domain for key path
            message_id: Email Message-ID for key path
            filename: Original filename
            content_type: MIME content type

        Returns:
            S3AttachmentInfo with bucket, key, url, and optional presigned_url

        Raises:
            S3UploadError: If upload fails
        """
        key = self._build_key(domain, message_id, filename)
        bucket = self.bucket

        try:
            async with self._session.create_client("s3", **self._client_kwargs()) as client:
                await client.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=content,
                    ContentType=content_type,
                )

                presigned_url = None
                if self.settings.s3_presigned_urls:
                    presigned_url = await client.generate_presigned_url(
                        "get_object",
                        Params={"Bucket": bucket, "Key": key},
                        ExpiresIn=self.settings.s3_presigned_url_expiry,
                    )

                logger.info(f"Uploaded attachment {filename} to s3://{bucket}/{key}")

                return S3AttachmentInfo(
                    bucket=bucket,
                    key=key,
                    url=self._build_url(key),
                    presigned_url=presigned_url,
                )

        except Exception as e:
            logger.warning(f"S3 upload failed for {filename}: {e}")
            raise S3UploadError(f"Failed to upload {filename}: {e}", filename, cause=e) from e

    async def upload_raw_message(
        self,
        content: bytes,
        domain: str,
        message_id: str,
        received_at: datetime | None = None,
    ) -> S3RawMessageInfo:
        """Upload the complete raw MIME message to S3.

        Args:
            content: Raw RFC 5322 message bytes exactly as received
            domain: Email domain for key path
            message_id: Email Message-ID for key path
            received_at: Receive time used for date partitioning (default: now)

        Returns:
            S3RawMessageInfo with bucket, key, url, size, and optional presigned_url

        Raises:
            S3UploadError: If upload fails
        """
        key = self._build_raw_key(domain, message_id, received_at)
        bucket = self.bucket

        try:
            async with self._session.create_client("s3", **self._client_kwargs()) as client:
                await client.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=content,
                    ContentType="message/rfc822",
                )

                presigned_url = None
                if self.settings.s3_presigned_urls:
                    presigned_url = await client.generate_presigned_url(
                        "get_object",
                        Params={"Bucket": bucket, "Key": key},
                        ExpiresIn=self.settings.s3_presigned_url_expiry,
                    )

                logger.info(f"Preserved raw message {message_id} at s3://{bucket}/{key}")

                return S3RawMessageInfo(
                    bucket=bucket,
                    key=key,
                    url=self._build_url(key),
                    size=len(content),
                    presigned_url=presigned_url,
                )

        except Exception as e:
            logger.warning(f"S3 raw message upload failed for {message_id}: {e}")
            raise S3UploadError(
                f"Failed to preserve raw message {message_id}: {e}", key, cause=e
            ) from e
