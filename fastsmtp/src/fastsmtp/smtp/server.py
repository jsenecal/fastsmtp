"""SMTP server implementation using aiosmtpd."""

import base64
import logging
import uuid
from email import message_from_bytes
from email.message import Message

import idna
from aiosmtpd.controller import Controller
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

        # Extract base payload (same for all recipients)
        base_payload = extract_email_payload(message, envelope, self.settings)
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


def extract_email_payload(
    message: Message,
    envelope: Envelope,
    settings: Settings | None = None,
) -> dict:
    """Extract email content into a webhook payload.

    Args:
        message: Parsed email message
        envelope: SMTP envelope
        settings: Application settings (for attachment size limits)
    """
    from typing import Any

    settings = settings or get_settings()
    max_attachment_size = settings.webhook_max_attachment_size

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

                # Include base64-encoded content if within size limit
                if isinstance(part_payload, bytes) and size <= max_attachment_size:
                    attachment_info["content"] = base64.b64encode(part_payload).decode("ascii")
                    attachment_info["content_transfer_encoding"] = "base64"

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

    # Enforce maximum payload size
    max_payload_size = settings.webhook_max_payload_size
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
        self.controller: Controller | None = None
        self.tls_controller: Controller | None = None

    def start(self) -> None:
        """Start the SMTP server(s)."""
        from fastsmtp.smtp.tls import get_tls_context_from_settings

        # Start plain SMTP server
        self.controller = Controller(
            self.handler,
            hostname=self.settings.smtp_host,
            port=self.settings.smtp_port,
            data_size_limit=self.settings.smtp_max_message_size,
        )
        self.controller.start()
        max_size_mb = self.settings.smtp_max_message_size / (1024 * 1024)
        logger.info(
            f"SMTP server started on {self.settings.smtp_host}:{self.settings.smtp_port} "
            f"(max message size: {max_size_mb:.1f}MB)"
        )

        # Start TLS SMTP server if configured
        tls_context = get_tls_context_from_settings(self.settings)
        if tls_context:
            self.tls_controller = Controller(
                self.handler,
                hostname=self.settings.smtp_host,
                port=self.settings.smtp_tls_port,
                ssl_context=tls_context,
                data_size_limit=self.settings.smtp_max_message_size,
            )
            self.tls_controller.start()
            logger.info(
                f"SMTP TLS server started on "
                f"{self.settings.smtp_host}:{self.settings.smtp_tls_port}"
            )

            # Also enable STARTTLS on the plain server
            if self.settings.smtp_require_starttls:
                logger.info("STARTTLS required for plain SMTP connections")

    def stop(self) -> None:
        """Stop the SMTP server(s)."""
        if self.controller:
            self.controller.stop()
            logger.info("SMTP server stopped")
        if self.tls_controller:
            self.tls_controller.stop()
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
