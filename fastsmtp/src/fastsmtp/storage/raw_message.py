"""Preservation of complete raw MIME messages in S3."""

import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any

from fastsmtp.storage.s3 import S3RawMessageInfo, S3Storage, S3UploadError

if TYPE_CHECKING:
    from fastsmtp.config import Settings
    from fastsmtp.db.models import Domain

logger = logging.getLogger(__name__)


def should_preserve_raw(
    domain: "Domain",
    rule_preserve_raw: bool,
    settings: "Settings",
) -> bool:
    """Decide whether a recipient's raw message should be preserved.

    A matching rule can only turn preservation on. Otherwise the domain's
    own setting applies, and a domain that leaves it unset inherits the
    global default.
    """
    if rule_preserve_raw:
        return True
    if domain.preserve_raw_message is not None:
        return bool(domain.preserve_raw_message)
    return settings.preserve_raw_message


class RawMessagePreserver:
    """Uploads a message's raw MIME exactly once per SMTP transaction.

    A single message can fan out to several recipients across several
    domains, but the archived bytes are identical, so the first recipient
    that asks for preservation triggers the upload and the rest reuse it.
    """

    def __init__(
        self,
        content: bytes,
        message_id: str,
        s3_storage: S3Storage | None,
        settings: "Settings",
        received_at: datetime | None = None,
    ):
        self.content = content
        self.message_id = message_id
        self.s3_storage = s3_storage
        self.settings = settings
        self.received_at = received_at
        self._info: S3RawMessageInfo | None = None
        self._attempted = False

    async def preserve(self, domain: str) -> S3RawMessageInfo | None:
        """Preserve the raw message, reusing an earlier upload if there was one.

        Args:
            domain: Domain used for the archive key path

        Returns:
            Information about the stored object, or None if preservation was
            skipped or failed while optional.

        Raises:
            S3UploadError: If preservation fails and preserve_raw_required is set
        """
        if self._attempted:
            return self._info

        self._attempted = True

        if self.s3_storage is None:
            message = f"Cannot preserve raw message {self.message_id}: S3 storage is not configured"
            if self.settings.preserve_raw_required:
                raise S3UploadError(message, self.message_id)
            logger.warning(message)
            return None

        try:
            self._info = await self.s3_storage.upload_raw_message(
                content=self.content,
                domain=domain,
                message_id=self.message_id,
                received_at=self.received_at,
            )
        except S3UploadError:
            if self.settings.preserve_raw_required:
                raise
            logger.warning(
                f"Raw message preservation failed for {self.message_id}, continuing delivery"
            )
            return None

        return self._info

    @staticmethod
    def payload_block(info: S3RawMessageInfo) -> dict[str, Any]:
        """Build the webhook payload block describing the preserved message."""
        block: dict[str, Any] = {
            "storage": "s3",
            "bucket": info.bucket,
            "key": info.key,
            "url": info.url,
            "size": info.size,
        }
        if info.presigned_url:
            block["presigned_url"] = info.presigned_url
        return block
