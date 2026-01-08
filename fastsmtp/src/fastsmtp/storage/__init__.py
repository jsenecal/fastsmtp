"""Storage backends for attachments."""

from fastsmtp.storage.s3 import S3AttachmentInfo, S3Storage, S3UploadError

__all__ = ["S3AttachmentInfo", "S3Storage", "S3UploadError"]
