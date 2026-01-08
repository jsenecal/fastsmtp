# S3 Attachment Storage Design

**Issue:** #33 - Optional S3-style storage for attachments
**Date:** 2026-01-08
**Status:** Approved

## Overview

Add optional S3-compatible object storage for email attachments. When configured, attachments are uploaded to S3/MinIO/Ceph and webhook payloads include bucket metadata instead of base64-encoded content.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Default behavior | Upload all attachments to S3 when configured | Simplicity, predictable payload structure |
| Failure handling | Fallback to inline base64 | Resilience, no data loss |
| Presigned URLs | Optional, default off | Security, not all receivers need direct access |
| Key structure | Domain-based: `{prefix}/{domain}/{message_id}/{filename}` | Multi-tenant friendly, enables per-domain lifecycle policies |
| S3 client library | aiobotocore | Mature, async, full S3 API support |
| Cleanup strategy | External S3 lifecycle policies | Separation of concerns, reliability |

## Configuration

New settings in `config.py`:

```python
# S3 Attachment Storage
attachment_storage: Literal["inline", "s3"] = Field(
    default="inline",
    description="Storage backend for attachments: 'inline' (base64 in payload) or 's3'",
)
s3_endpoint_url: str | None = Field(
    default=None,
    description="S3 endpoint URL (for MinIO/Ceph). None = AWS default",
)
s3_bucket: str | None = Field(
    default=None,
    description="S3 bucket name for attachments",
)
s3_access_key: SecretStr | None = Field(
    default=None,
    description="S3 access key ID",
)
s3_secret_key: SecretStr | None = Field(
    default=None,
    description="S3 secret access key",
)
s3_region: str = Field(
    default="us-east-1",
    description="S3 region",
)
s3_prefix: str = Field(
    default="attachments",
    description="S3 key prefix for attachments",
)
s3_presigned_urls: bool = Field(
    default=False,
    description="Include presigned URLs in webhook payload",
)
s3_presigned_url_expiry: int = Field(
    default=3600,
    description="Presigned URL expiry in seconds",
)
```

**Validation:** If `attachment_storage=s3`, require `s3_bucket`, `s3_access_key`, and `s3_secret_key`.

**Renamed settings** (only apply to inline mode):
- `webhook_max_attachment_size` → `webhook_max_inline_attachment_size`
- `webhook_max_payload_size` → `webhook_max_inline_payload_size`

## S3 Client Module

New file: `src/fastsmtp/storage/__init__.py` and `src/fastsmtp/storage/s3.py`

```python
class S3Storage:
    """Async S3 storage client for attachments."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._session: AioSession | None = None

    async def upload_attachment(
        self,
        content: bytes,
        domain: str,
        message_id: str,
        filename: str,
        content_type: str,
    ) -> S3AttachmentInfo:
        """Upload attachment to S3.

        Returns S3AttachmentInfo with bucket, key, and optional presigned URL.
        Raises S3UploadError on failure.
        """

    async def generate_presigned_url(self, key: str) -> str:
        """Generate presigned URL for an S3 object."""

    async def close(self):
        """Close the S3 session."""


@dataclass
class S3AttachmentInfo:
    bucket: str
    key: str
    url: str  # Direct S3 URL (not presigned)
    presigned_url: str | None  # Only if enabled


class S3UploadError(Exception):
    """Raised when S3 upload fails."""
    def __init__(self, message: str, filename: str, cause: Exception | None = None):
        self.filename = filename
        self.cause = cause
        super().__init__(message)
```

### S3 Key Structure

Format: `{prefix}/{domain}/{sanitized_message_id}/{filename}`

Example: `attachments/example.com/abc123def456/report.pdf`

The message_id is sanitized to remove `<>` and special characters unsuitable for S3 keys.

## Webhook Payload Changes

### Inline Storage (default, unchanged)

```json
{
  "attachments": [
    {
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size": 102400,
      "storage": "inline",
      "content": "JVBERi0xLjQK...",
      "content_transfer_encoding": "base64"
    }
  ]
}
```

### S3 Storage

```json
{
  "attachments": [
    {
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size": 102400,
      "storage": "s3",
      "bucket": "fastsmtp-attachments",
      "key": "attachments/example.com/abc123/report.pdf",
      "url": "https://s3.us-east-1.amazonaws.com/fastsmtp-attachments/attachments/...",
      "presigned_url": "https://...?X-Amz-Algorithm=..."
    }
  ]
}
```

Note: `presigned_url` only included when `s3_presigned_urls=true`.

### S3 Fallback (S3 configured but upload failed)

```json
{
  "attachments": [
    {
      "filename": "report.pdf",
      "content_type": "application/pdf",
      "size": 102400,
      "storage": "inline",
      "storage_fallback": true,
      "content": "JVBERi0xLjQK...",
      "content_transfer_encoding": "base64"
    }
  ]
}
```

The `storage_fallback: true` flag indicates S3 was configured but failed for this attachment.

## SMTP Server Integration

### Function Signature Change

The `extract_email_payload` function becomes async to support S3 uploads:

```python
async def extract_email_payload(
    message: Message,
    envelope: Envelope,
    settings: Settings | None = None,
    s3_storage: S3Storage | None = None,
    domain: str | None = None,
) -> dict:
```

### Processing Flow

1. Check if `attachment_storage=s3` and S3 client available
2. For each attachment:
   - Extract content, filename, content_type, size
   - If S3 enabled: attempt `s3_storage.upload_attachment()`
   - On success: add S3 metadata (`bucket`, `key`, `url`, `presigned_url`)
   - On failure: log warning, add inline base64 with `storage_fallback: true`
3. If S3 disabled: use existing inline base64 logic

### Size Limits

- `webhook_max_inline_attachment_size`: Only applies to inline storage
- `webhook_max_inline_payload_size`: Only applies to inline storage
- S3 storage has no FastSMTP-imposed limits (S3's own limits apply)

## Error Handling

### Logging

| Level | Condition | Message |
|-------|-----------|---------|
| INFO | S3 upload successful | `Uploaded attachment {filename} to s3://{bucket}/{key}` |
| WARNING | S3 upload failed, fallback | `S3 upload failed for {filename}, falling back to inline: {error}` |
| ERROR | S3 client init failed | `Failed to initialize S3 client: {error}` |

### Graceful Degradation

- S3 client initialization failure: log error, don't crash, all attachments go inline
- Individual upload failure: isolated, doesn't affect other attachments
- No retries during message processing (keeps SMTP response time reasonable)

## Testing Strategy

### Unit Tests (`tests/test_storage_s3.py`)

- `S3Storage.upload_attachment` with mocked aiobotocore
- `S3Storage.generate_presigned_url` verification
- Key sanitization (special characters in message_id)
- Fallback to inline on upload failure
- Config validation (require credentials when S3 enabled)

### Integration Tests (`tests/test_storage_s3_integration.py`)

- MinIO container via testcontainers
- Full upload/download cycle
- Presigned URL access verification
- Multipart email with attachments end-to-end

### SMTP Server Tests (extend existing)

- `test_email_with_attachment_s3_storage`
- `test_email_with_attachment_s3_fallback`
- `test_extract_email_payload_async`

Mark integration tests with `pytest.mark.integration` for optional execution.

## Dependencies

Add to `pyproject.toml`:

```toml
aiobotocore = "^2.9.0"
```

## File Changes Summary

| File | Change |
|------|--------|
| `src/fastsmtp/config.py` | Add S3 settings, rename inline size limits |
| `src/fastsmtp/storage/__init__.py` | New module |
| `src/fastsmtp/storage/s3.py` | New S3Storage class |
| `src/fastsmtp/smtp/server.py` | Make `extract_email_payload` async, integrate S3 |
| `tests/test_storage_s3.py` | New unit tests |
| `tests/test_storage_s3_integration.py` | New integration tests |

## S3 Lifecycle Policy (Documentation)

Users should configure S3 lifecycle policies externally. Example for 90-day retention:

```json
{
  "Rules": [
    {
      "ID": "Delete attachments after 90 days",
      "Status": "Enabled",
      "Filter": {
        "Prefix": "attachments/"
      },
      "Expiration": {
        "Days": 90
      }
    }
  ]
}
```

## Implementation Order

1. Add configuration settings and validation
2. Implement `S3Storage` class with upload and presigned URL generation
3. Rename existing size limit settings
4. Make `extract_email_payload` async and integrate S3
5. Add unit tests with mocked S3
6. Add integration tests with MinIO container
7. Update documentation
