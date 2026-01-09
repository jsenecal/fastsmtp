"""SMTP server implementation using aiosmtpd."""

import asyncio
import base64
import contextlib
import logging
import uuid
from email import message_from_bytes
from email.message import Message
from typing import TYPE_CHECKING

import idna

if TYPE_CHECKING:
    from fastsmtp.smtp.tls import TLSContextManager
    from fastsmtp.storage.s3 import S3Storage
from aiosmtpd.controller import UnthreadedController
from aiosmtpd.smtp import SMTP, Envelope, Session
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import Domain, Recipient
from fastsmtp.db.session import async_session
from fastsmtp.metrics.definitions import (
    AUTH_RESULTS,
    SMTP_MESSAGE_SIZE,
    SMTP_MESSAGES_TOTAL,
    SMTP_RATE_LIMITED,
)
from fastsmtp.smtp.rate_limiter import get_smtp_rate_limiter
from fastsmtp.smtp.validation import EmailAuthResult, validate_email_auth

logger = logging.getLogger(__name__)


async def lookup_recipient(
    address: str,
    session: AsyncSession,
) -> tuple[Domain | None, Recipient | None, str | None]:
    """Look up domain and recipient for an email address.

    Args:
        address: Email address to look up
        session: Database session

    Returns:
        Tuple of (domain, recipient, error_message).
        error_message is None on success, otherwise contains rejection reason.
    """
    if "@" not in address:
        return None, None, "Invalid recipient address"

    local_part, domain_name = address.rsplit("@", 1)
    local_part_lower = local_part.lower()

    # Normalize international domain names (IDN) to ASCII punycode
    # This ensures "example.com" and "example.com" (with Cyrillic chars) are handled correctly
    try:
        domain_name = idna.encode(domain_name.lower()).decode("ascii")
    except idna.core.InvalidCodepoint:
        return None, None, "Invalid domain name encoding"
    except idna.core.InvalidCodepointContext:
        return None, None, "Invalid domain name encoding"

    # Look up domain with recipients (excluding soft-deleted)
    stmt = (
        select(Domain)
        .options(selectinload(Domain.recipients))
        .where(
            Domain.domain_name == domain_name,
            Domain.is_enabled.is_(True),
            Domain.deleted_at.is_(None),
        )
    )
    result = await session.execute(stmt)
    domain = result.scalar_one_or_none()

    if not domain:
        return None, None, f"Domain {domain_name} not configured"

    # Find matching recipient: specific match first, then catch-all
    # Filter out disabled and soft-deleted recipients
    specific_recipient = None
    catchall_recipient = None

    for recipient in domain.recipients:
        if not recipient.is_enabled or recipient.deleted_at is not None:
            continue
        if recipient.local_part is None:
            catchall_recipient = recipient
        elif recipient.local_part.lower() == local_part_lower:
            specific_recipient = recipient
            break

    matched_recipient = specific_recipient or catchall_recipient

    if not matched_recipient:
        return domain, None, f"User {local_part} not found"

    return domain, matched_recipient, None


class FastSMTPHandler:
    """Handler for incoming SMTP messages.

    Messages are persisted directly to the database in handle_DATA before
    acknowledging receipt to the SMTP client. This ensures no data loss.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

        # S3 storage client (initialized if attachment_storage == "s3")
        self._s3_storage = None
        if self.settings.attachment_storage == "s3":
            try:
                from fastsmtp.storage.s3 import S3Storage

                self._s3_storage = S3Storage(self.settings)
                logger.info("S3 attachment storage initialized")
            except Exception as e:
                logger.error(f"Failed to initialize S3 storage: {e}")

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        """Validate recipient address against configured domains."""
        # Check recipient limit per message
        if len(envelope.rcpt_tos) >= self.settings.smtp_rate_limit_recipients_per_message:
            logger.warning(f"Recipient limit exceeded: {len(envelope.rcpt_tos)} recipients")
            SMTP_RATE_LIMITED.labels(type="recipient").inc()
            return "452 Too many recipients"

        async with async_session() as db_session:
            domain, recipient, error = await lookup_recipient(address, db_session)

            if error:
                logger.debug(f"Rejecting recipient {address}: {error}")
                return f"550 {error}"

        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
    ) -> str:
        """Process incoming email data and persist to database.

        Messages are persisted to the database before returning 250 OK to ensure
        no data loss if the server crashes. The webhook worker will then process
        the deliveries asynchronously.
        """
        client_ip = session.peer[0] if session.peer else "unknown"
        mail_from = envelope.mail_from or ""
        helo = session.host_name or ""

        # Check rate limit for messages
        rate_limiter = get_smtp_rate_limiter()
        allowed, error = rate_limiter.check_message(client_ip)
        if not allowed:
            logger.warning(f"Rate limit exceeded for {client_ip}: {error}")
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return f"421 {error}"

        # Check queue backpressure
        from fastsmtp.webhook.queue import check_queue_backpressure

        async with async_session() as db_session:
            is_backpressured, queue_count = await check_queue_backpressure(
                db_session, self.settings
            )
        if is_backpressured:
            logger.warning(
                f"Queue backpressure triggered: {queue_count} pending deliveries "
                f"(max: {self.settings.queue_max_pending})"
            )
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            if self.settings.queue_backpressure_action == "drop":
                # Accept but don't process - log for monitoring
                logger.info(f"Dropping message from {mail_from} due to backpressure")
                return "250 OK (backpressure: message dropped)"
            else:
                # Reject with temporary error so sender can retry
                return "451 Service temporarily unavailable - queue full, try again later"

        # Ensure content is bytes
        content = envelope.content
        if content is None:
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return "550 Empty message"
        if isinstance(content, str):
            content = content.encode("utf-8")
        message_size = len(content)

        logger.info(
            f"Received message from {mail_from} to {envelope.rcpt_tos} "
            f"(client: {client_ip}, size: {message_size} bytes)"
        )

        # Record message size metric
        SMTP_MESSAGE_SIZE.observe(message_size)

        # Parse the message
        try:
            message = message_from_bytes(content)
        except Exception as e:
            logger.error(f"Failed to parse message: {e}")
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return "550 Failed to parse message"

        # Get Message-ID (use UUID if not present for reliable deduplication)
        message_id = message.get("Message-ID") or f"<{uuid.uuid4()}@fastsmtp>"

        # Run email authentication
        auth_result = await validate_email_auth(
            message=content,
            client_ip=client_ip,
            mail_from=mail_from,
            helo=helo,
            verify_dkim_enabled=self.settings.smtp_verify_dkim,
            verify_spf_enabled=self.settings.smtp_verify_spf,
        )

        logger.info(
            f"Message {message_id}: DKIM={auth_result.dkim_result}, SPF={auth_result.spf_result}"
        )

        # Record authentication metrics
        AUTH_RESULTS.labels(type="dkim", result=auth_result.dkim_result).inc()
        AUTH_RESULTS.labels(type="spf", result=auth_result.spf_result).inc()

        # Check if we should reject based on auth results (global settings)
        if self.settings.smtp_reject_dkim_fail and auth_result.dkim_result == "fail":
            logger.warning(f"Rejecting message {message_id}: DKIM failed")
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return "550 DKIM verification failed"

        if self.settings.smtp_reject_spf_fail and auth_result.spf_result == "fail":
            logger.warning(f"Rejecting message {message_id}: SPF failed")
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return "550 SPF verification failed"

        # Process message and persist to database BEFORE returning 250 OK
        # This ensures no data loss if the server crashes
        try:
            deliveries_created = await self._process_and_persist_message(
                envelope=envelope,
                message=message,
                message_id=message_id,
                auth_result=auth_result,
                client_ip=client_ip,
            )
        except Exception as e:
            logger.exception(f"Failed to persist message {message_id}: {e}")
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return "451 Temporary failure, please retry"

        if deliveries_created == 0:
            # All recipients were dropped by rules or had errors
            logger.warning(f"Message {message_id}: no deliveries created (all dropped)")
            SMTP_MESSAGES_TOTAL.labels(result="dropped").inc()
            return "250 Message accepted"

        SMTP_MESSAGES_TOTAL.labels(result="accepted").inc()
        logger.info(f"Message {message_id}: {deliveries_created} deliveries queued")
        return "250 Message accepted for delivery"

    async def _process_and_persist_message(
        self,
        envelope: Envelope,
        message: Message,
        message_id: str,
        auth_result: EmailAuthResult,
        client_ip: str,
    ) -> int:
        """Process message for each recipient and persist deliveries to database.

        Args:
            envelope: SMTP envelope
            message: Parsed email message
            message_id: Message-ID header value
            auth_result: Email authentication result
            client_ip: Client IP address

        Returns:
            Number of deliveries created
        """
        # Import here to avoid circular import
        from fastsmtp.rules.engine import evaluate_rules
        from fastsmtp.webhook.queue import enqueue_delivery

        # Determine domain for S3 storage key (use first recipient's domain)
        recipient_domain = None
        if envelope.rcpt_tos:
            first_rcpt = envelope.rcpt_tos[0]
            if "@" in first_rcpt:
                recipient_domain = first_rcpt.rsplit("@", 1)[1].lower()

        # Get S3 storage if enabled
        s3_storage = None
        if self.settings.attachment_storage == "s3" and hasattr(self, "_s3_storage"):
            s3_storage = self._s3_storage

        # Extract base payload (same for all recipients)
        base_payload = await extract_email_payload(
            message, envelope, self.settings, s3_storage=s3_storage, domain=recipient_domain
        )
        base_payload["client_ip"] = client_ip
        base_payload["dkim_result"] = auth_result.dkim_result
        base_payload["dkim_domain"] = auth_result.dkim_domain
        base_payload["spf_result"] = auth_result.spf_result
        base_payload["spf_domain"] = auth_result.spf_domain

        deliveries_created = 0

        async with async_session() as db_session:
            # Process each recipient
            for rcpt_to in envelope.rcpt_tos:
                domain, recipient, error = await lookup_recipient(rcpt_to, db_session)

                if error or not domain or not recipient:
                    logger.warning(f"Message {message_id}: skipping recipient {rcpt_to}: {error}")
                    continue

                # Evaluate rules for this domain
                rule_result = await evaluate_rules(
                    session=db_session,
                    domain_id=domain.id,
                    message=message,
                    payload=base_payload,
                    auth_result=auth_result,
                )

                # Check if message should be dropped
                if rule_result.should_drop:
                    logger.info(f"Message {message_id}: dropped for {rcpt_to} by rules")
                    continue

                # Build recipient-specific payload
                payload = base_payload.copy()
                payload["tags"] = rule_result.tags
                payload["recipient"] = rcpt_to

                # Determine webhook URL (rule override takes precedence)
                webhook_url = rule_result.webhook_url_override or recipient.webhook_url

                # Enqueue delivery to database
                await enqueue_delivery(
                    session=db_session,
                    domain_id=domain.id,
                    recipient_id=recipient.id,
                    message_id=message_id,
                    webhook_url=webhook_url,
                    payload=payload,
                    auth_result=auth_result,
                    settings=self.settings,
                )
                deliveries_created += 1

            # Commit all deliveries in a single transaction
            await db_session.commit()

        return deliveries_created


async def extract_email_payload(
    message: Message,
    envelope: Envelope,
    settings: Settings | None = None,
    s3_storage: "S3Storage | None" = None,
    domain: str | None = None,
) -> dict:
    """Extract email content into a webhook payload.

    Args:
        message: Parsed email message
        envelope: SMTP envelope
        settings: Application settings (for attachment size limits)
        s3_storage: S3 storage client (if S3 enabled)
        domain: Email domain for S3 key path
    """
    from typing import Any

    settings = settings or get_settings()
    max_inline_attachment_size = settings.webhook_max_inline_attachment_size

    # Get basic headers
    payload: dict[str, Any] = {
        "message_id": message.get("Message-ID", ""),
        "from": message.get("From", ""),
        "to": message.get("To", ""),
        "cc": message.get("Cc", ""),
        "subject": message.get("Subject", ""),
        "date": message.get("Date", ""),
        "reply_to": message.get("Reply-To", ""),
        "envelope_from": envelope.mail_from,
        "envelope_to": envelope.rcpt_tos,
        "headers": dict(message.items()),
    }

    # Extract body
    attachments: list[dict[str, Any]] = []
    body_text = ""
    body_html = ""

    if message.is_multipart():
        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")

            if "attachment" in content_disposition:
                # Handle attachment
                filename = part.get_filename() or "unnamed"
                part_payload = part.get_payload(decode=True)
                size = len(part_payload) if isinstance(part_payload, bytes) else 0

                attachment_info: dict[str, Any] = {
                    "filename": filename,
                    "content_type": content_type,
                    "size": size,
                }

                if isinstance(part_payload, bytes) and s3_storage and domain:
                    # Upload to S3
                    try:
                        s3_info = await s3_storage.upload_attachment(
                            content=part_payload,
                            domain=domain,
                            message_id=message.get("Message-ID", "unknown"),
                            filename=filename,
                            content_type=content_type,
                        )
                        attachment_info["storage"] = "s3"
                        attachment_info["bucket"] = s3_info.bucket
                        attachment_info["key"] = s3_info.key
                        attachment_info["url"] = s3_info.url
                        if s3_info.presigned_url:
                            attachment_info["presigned_url"] = s3_info.presigned_url
                    except Exception as e:
                        # Fallback to inline on S3 failure
                        logger.warning(
                            f"S3 upload failed for {filename}, falling back to inline: {e}"
                        )
                        attachment_info["storage"] = "inline"
                        attachment_info["storage_fallback"] = True
                        if size <= max_inline_attachment_size:
                            attachment_info["content"] = base64.b64encode(part_payload).decode(
                                "ascii"
                            )
                            attachment_info["content_transfer_encoding"] = "base64"
                elif isinstance(part_payload, bytes) and size <= max_inline_attachment_size:
                    # Inline storage
                    attachment_info["storage"] = "inline"
                    attachment_info["content"] = base64.b64encode(part_payload).decode("ascii")
                    attachment_info["content_transfer_encoding"] = "base64"
                else:
                    # Metadata only (too large for inline, no S3)
                    attachment_info["storage"] = "inline"

                attachments.append(attachment_info)
            elif content_type == "text/plain":
                payload_bytes = part.get_payload(decode=True)
                if isinstance(payload_bytes, bytes):
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_text = payload_bytes.decode(charset)
                    except Exception:
                        body_text = payload_bytes.decode("utf-8", errors="replace")
            elif content_type == "text/html":
                payload_bytes = part.get_payload(decode=True)
                if isinstance(payload_bytes, bytes):
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_html = payload_bytes.decode(charset)
                    except Exception:
                        body_html = payload_bytes.decode("utf-8", errors="replace")
    else:
        # Simple message
        charset = message.get_content_charset() or "utf-8"
        body_bytes = message.get_payload(decode=True)
        body_str = ""
        if isinstance(body_bytes, bytes):
            try:
                body_str = body_bytes.decode(charset)
            except Exception:
                body_str = body_bytes.decode("utf-8", errors="replace")
        elif isinstance(body_bytes, str):
            body_str = body_bytes

        if message.get_content_type() == "text/html":
            body_html = body_str
        else:
            body_text = body_str

    payload["body_text"] = body_text
    payload["body_html"] = body_html
    payload["attachments"] = attachments
    payload["has_attachments"] = len(attachments) > 0

    # Enforce maximum payload size for inline storage
    max_payload_size = settings.webhook_max_inline_payload_size
    payload = _enforce_payload_size_limit(payload, max_payload_size)

    return payload


def _enforce_payload_size_limit(payload: dict, max_size: int) -> dict:
    """Enforce maximum payload size by truncating body and removing attachment content.

    Args:
        payload: The webhook payload dict
        max_size: Maximum payload size in bytes

    Returns:
        Payload within size limits
    """
    import json

    # Estimate current size (JSON serialization overhead)
    current_size = len(json.dumps(payload, default=str))

    if current_size <= max_size:
        return payload

    # First pass: remove attachment content (keep metadata)
    for attachment in payload.get("attachments", []):
        if "content" in attachment:
            del attachment["content"]
            if "content_transfer_encoding" in attachment:
                del attachment["content_transfer_encoding"]

    current_size = len(json.dumps(payload, default=str))
    if current_size <= max_size:
        logger.debug(f"Payload reduced to {current_size} bytes by removing attachment content")
        return payload

    # Second pass: truncate body text and html
    excess = current_size - max_size
    body_text = payload.get("body_text", "")
    body_html = payload.get("body_html", "")

    # Truncate bodies proportionally
    total_body_len = len(body_text) + len(body_html)
    if total_body_len > excess:
        text_ratio = len(body_text) / total_body_len if total_body_len > 0 else 0.5
        text_trim = int(excess * text_ratio)
        html_trim = excess - text_trim

        if len(body_text) > text_trim:
            payload["body_text"] = body_text[: len(body_text) - text_trim] + "... [truncated]"
        if len(body_html) > html_trim:
            payload["body_html"] = body_html[: len(body_html) - html_trim] + "... [truncated]"

        logger.debug(f"Payload body truncated to fit within {max_size} bytes")

    return payload


class SMTPServer:
    """FastSMTP server wrapper with optional TLS support.

    Uses UnthreadedController to run the SMTP server on the same event loop
    as the rest of the application. This is critical for async database
    operations since SQLAlchemy's AsyncEngine binds to a specific event loop.

    Messages are persisted directly to the database in handle_DATA before
    acknowledging receipt. This ensures no data loss if the server crashes.
    The webhook worker processes deliveries asynchronously from the database.
    """

    def __init__(
        self,
        settings: Settings | None = None,
    ):
        self.settings = settings or get_settings()
        self.handler = FastSMTPHandler(self.settings)
        self.controller: UnthreadedController | None = None
        self.tls_controller: UnthreadedController | None = None
        self._server: asyncio.AbstractServer | None = None
        self._tls_server: asyncio.AbstractServer | None = None
        self._tls_manager: TLSContextManager | None = None
        self._hot_reload_task: asyncio.Task | None = None

    async def _restart_tls_controller(self) -> None:
        """Restart the TLS controller with a new context."""
        if not self._tls_manager or not self._tls_manager.context:
            return

        # Stop existing TLS server
        if self._tls_server:
            self._tls_server.close()
            await self._tls_server.wait_closed()
            logger.info("SMTP TLS server stopped for reload")

        # Create new TLS controller with updated context
        loop = asyncio.get_running_loop()
        self.tls_controller = UnthreadedController(
            self.handler,
            hostname=self.settings.smtp_host,
            port=self.settings.smtp_tls_port,
            loop=loop,
            ssl_context=self._tls_manager.context,
            data_size_limit=self.settings.smtp_max_message_size,
        )
        # Start the server by awaiting _create_server() directly
        self._tls_server = await self.tls_controller._create_server()
        logger.info(
            f"SMTP TLS server restarted on {self.settings.smtp_host}:{self.settings.smtp_tls_port}"
        )

    async def _tls_hot_reload_loop(self) -> None:
        """Monitor TLS certificates and restart controller on changes."""
        if not self._tls_manager:
            return

        interval = self.settings.smtp_tls_reload_interval
        logger.info(f"TLS hot-reload enabled, checking every {interval}s")

        while True:
            try:
                await asyncio.sleep(interval)
                if self._tls_manager._files_changed():
                    logger.info("TLS certificate files changed, reloading...")
                    new_context = self._tls_manager.load_context()
                    if new_context:
                        await self._restart_tls_controller()
                    else:
                        logger.error("Failed to reload TLS context, keeping old config")
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in TLS hot-reload loop")

        logger.info("TLS hot-reload monitor stopped")

    async def start(self) -> None:
        """Start the SMTP server(s).

        This method must be called from within a running asyncio event loop.
        Uses UnthreadedController to run on the same loop, ensuring database
        operations work correctly with SQLAlchemy's AsyncEngine.
        """
        from fastsmtp.smtp.tls import TLSContextManager

        loop = asyncio.get_running_loop()

        # Start plain SMTP server using UnthreadedController
        self.controller = UnthreadedController(
            self.handler,
            hostname=self.settings.smtp_host,
            port=self.settings.smtp_port,
            loop=loop,
            data_size_limit=self.settings.smtp_max_message_size,
        )
        # Await _create_server() directly instead of calling begin()
        # This properly integrates with the running event loop
        self._server = await self.controller._create_server()

        max_size_mb = self.settings.smtp_max_message_size / (1024 * 1024)
        logger.info(
            f"SMTP server started on {self.settings.smtp_host}:{self.settings.smtp_port} "
            f"(max message size: {max_size_mb:.1f}MB)"
        )

        # Start TLS SMTP server if configured
        self._tls_manager = TLSContextManager(self.settings)
        tls_context = self._tls_manager.load_context()
        if tls_context:
            self.tls_controller = UnthreadedController(
                self.handler,
                hostname=self.settings.smtp_host,
                port=self.settings.smtp_tls_port,
                loop=loop,
                ssl_context=tls_context,
                data_size_limit=self.settings.smtp_max_message_size,
            )
            self._tls_server = await self.tls_controller._create_server()
            logger.info(
                f"SMTP TLS server started on "
                f"{self.settings.smtp_host}:{self.settings.smtp_tls_port}"
            )

            # Also enable STARTTLS on the plain server
            if self.settings.smtp_require_starttls:
                logger.info("STARTTLS required for plain SMTP connections")

            # Start hot-reload monitoring if enabled
            if self.settings.smtp_tls_hot_reload:
                self._hot_reload_task = asyncio.create_task(self._tls_hot_reload_loop())

    async def stop(self) -> None:
        """Stop the SMTP server(s)."""
        # Stop hot-reload task
        if self._hot_reload_task and not self._hot_reload_task.done():
            self._hot_reload_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._hot_reload_task

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("SMTP server stopped")

        if self._tls_server:
            self._tls_server.close()
            await self._tls_server.wait_closed()
            logger.info("SMTP TLS server stopped")


async def find_recipient_for_address(
    address: str,
    db_session: AsyncSession,
) -> tuple[Domain | None, Recipient | None]:
    """Find the domain and recipient for an email address.

    Args:
        address: Email address to look up
        db_session: Database session

    Returns:
        Tuple of (domain, recipient). Both may be None if not found.
    """
    domain, recipient, _ = await lookup_recipient(address, db_session)
    return domain, recipient
