"""SMTP server implementation using aiosmtpd."""

import asyncio
import logging
from email import message_from_bytes
from email.message import Message

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import Domain, Recipient
from fastsmtp.db.session import async_session
from fastsmtp.smtp.validation import validate_email_auth

logger = logging.getLogger(__name__)


class FastSMTPHandler:
    """Handler for incoming SMTP messages."""

    def __init__(self, settings: Settings, message_queue: asyncio.Queue | None = None):
        self.settings = settings
        self.message_queue = message_queue

    async def handle_RCPT(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
        address: str,
        rcpt_options: list[str],
    ) -> str:
        """Validate recipient address against configured domains."""
        # Parse the recipient address
        if "@" not in address:
            return "550 Invalid recipient address"

        local_part, domain_name = address.rsplit("@", 1)
        domain_name = domain_name.lower()

        # Check if we handle this domain
        async with async_session() as db_session:
            stmt = (
                select(Domain)
                .options(selectinload(Domain.recipients))
                .where(Domain.domain_name == domain_name, Domain.is_enabled == True)  # noqa: E712
            )
            result = await db_session.execute(stmt)
            domain = result.scalar_one_or_none()

            if not domain:
                logger.debug(f"Rejecting recipient {address}: domain not configured")
                return f"550 Domain {domain_name} not configured"

            # Check if there's a matching recipient or catch-all
            has_recipient = False
            for recipient in domain.recipients:
                if not recipient.is_enabled:
                    continue
                if recipient.local_part is None:  # Catch-all
                    has_recipient = True
                    break
                if recipient.local_part.lower() == local_part.lower():
                    has_recipient = True
                    break

            if not has_recipient:
                logger.debug(f"Rejecting recipient {address}: no matching recipient")
                return f"550 User {local_part} not found"

        envelope.rcpt_tos.append(address)
        return "250 OK"

    async def handle_DATA(
        self,
        server: SMTP,
        session: Session,
        envelope: Envelope,
    ) -> str:
        """Process incoming email data."""
        client_ip = session.peer[0] if session.peer else "unknown"
        mail_from = envelope.mail_from or ""
        helo = session.host_name or ""

        logger.info(
            f"Received message from {mail_from} to {envelope.rcpt_tos} "
            f"(client: {client_ip}, size: {len(envelope.content)} bytes)"
        )

        # Parse the message
        try:
            message = message_from_bytes(envelope.content)
        except Exception as e:
            logger.error(f"Failed to parse message: {e}")
            return "550 Failed to parse message"

        # Get Message-ID
        message_id = message.get("Message-ID", f"<{id(envelope)}@fastsmtp>")

        # Run email authentication
        auth_result = await validate_email_auth(
            message=envelope.content,
            client_ip=client_ip,
            mail_from=mail_from,
            helo=helo,
            verify_dkim_enabled=self.settings.smtp_verify_dkim,
            verify_spf_enabled=self.settings.smtp_verify_spf,
        )

        logger.info(
            f"Message {message_id}: DKIM={auth_result.dkim_result}, SPF={auth_result.spf_result}"
        )

        # Check if we should reject based on auth results
        # This can be overridden per-domain, but we check global settings first
        if self.settings.smtp_reject_dkim_fail and auth_result.dkim_result == "fail":
            logger.warning(f"Rejecting message {message_id}: DKIM failed")
            return "550 DKIM verification failed"

        if self.settings.smtp_reject_spf_fail and auth_result.spf_result == "fail":
            logger.warning(f"Rejecting message {message_id}: SPF failed")
            return "550 SPF verification failed"

        # Queue the message for processing
        if self.message_queue:
            await self.message_queue.put({
                "envelope": envelope,
                "message": message,
                "message_id": message_id,
                "auth_result": auth_result,
                "client_ip": client_ip,
            })
            logger.debug(f"Message {message_id} queued for processing")
        else:
            logger.warning(f"Message {message_id} received but no queue configured")

        return "250 Message accepted for delivery"


def extract_email_payload(message: Message, envelope: Envelope) -> dict:
    """Extract email content into a webhook payload."""
    # Get basic headers
    payload = {
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
    if message.is_multipart():
        payload["body_text"] = ""
        payload["body_html"] = ""
        payload["attachments"] = []

        for part in message.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")

            if "attachment" in content_disposition:
                # Handle attachment
                filename = part.get_filename() or "unnamed"
                payload["attachments"].append({
                    "filename": filename,
                    "content_type": content_type,
                    "size": len(part.get_payload(decode=True) or b""),
                })
            elif content_type == "text/plain":
                charset = part.get_content_charset() or "utf-8"
                try:
                    payload["body_text"] = part.get_payload(decode=True).decode(charset)
                except Exception:
                    payload["body_text"] = part.get_payload(decode=True).decode(
                        "utf-8", errors="replace"
                    )
            elif content_type == "text/html":
                charset = part.get_content_charset() or "utf-8"
                try:
                    payload["body_html"] = part.get_payload(decode=True).decode(charset)
                except Exception:
                    payload["body_html"] = part.get_payload(decode=True).decode(
                        "utf-8", errors="replace"
                    )
    else:
        # Simple message
        charset = message.get_content_charset() or "utf-8"
        try:
            body = message.get_payload(decode=True)
            if isinstance(body, bytes):
                body = body.decode(charset)
        except Exception:
            body = message.get_payload(decode=True)
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")

        if message.get_content_type() == "text/html":
            payload["body_html"] = body
            payload["body_text"] = ""
        else:
            payload["body_text"] = body
            payload["body_html"] = ""

        payload["attachments"] = []

    payload["has_attachments"] = len(payload.get("attachments", [])) > 0

    return payload


class SMTPServer:
    """FastSMTP server wrapper with optional TLS support."""

    def __init__(
        self,
        settings: Settings | None = None,
        message_queue: asyncio.Queue | None = None,
    ):
        self.settings = settings or get_settings()
        self.message_queue = message_queue or asyncio.Queue()
        self.handler = FastSMTPHandler(self.settings, self.message_queue)
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
        )
        self.controller.start()
        logger.info(
            f"SMTP server started on {self.settings.smtp_host}:{self.settings.smtp_port}"
        )

        # Start TLS SMTP server if configured
        tls_context = get_tls_context_from_settings(self.settings)
        if tls_context:
            self.tls_controller = Controller(
                self.handler,
                hostname=self.settings.smtp_host,
                port=self.settings.smtp_tls_port,
                ssl_context=tls_context,
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

    async def get_message(self) -> dict:
        """Get the next message from the queue."""
        return await self.message_queue.get()


async def find_recipient_for_address(
    address: str,
    db_session,
) -> tuple[Domain | None, Recipient | None]:
    """Find the domain and recipient for an email address."""
    if "@" not in address:
        return None, None

    local_part, domain_name = address.rsplit("@", 1)
    domain_name = domain_name.lower()
    local_part = local_part.lower()

    stmt = (
        select(Domain)
        .options(selectinload(Domain.recipients))
        .where(Domain.domain_name == domain_name, Domain.is_enabled == True)  # noqa: E712
    )
    result = await db_session.execute(stmt)
    domain = result.scalar_one_or_none()

    if not domain:
        return None, None

    # Find specific recipient first, then fall back to catch-all
    specific_recipient = None
    catchall_recipient = None

    for recipient in domain.recipients:
        if not recipient.is_enabled:
            continue
        if recipient.local_part is None:
            catchall_recipient = recipient
        elif recipient.local_part.lower() == local_part:
            specific_recipient = recipient
            break

    return domain, specific_recipient or catchall_recipient
