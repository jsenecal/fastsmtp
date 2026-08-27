"""SMTP server implementation using aiosmtpd."""

import asyncio
import base64
import contextlib
import logging
import mimetypes
import re
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from email import message_from_bytes
from email.message import Message
from typing import TYPE_CHECKING, Any, NamedTuple, cast

import idna

if TYPE_CHECKING:
    from fastsmtp.smtp.tls import TLSContextManager
    from fastsmtp.storage.s3 import S3Storage
from aiosmtpd.controller import UnthreadedController
from aiosmtpd.smtp import SMTP, Envelope, Session, syntax
from sqlalchemy import Select, select
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
from fastsmtp.smtp.validation import (
    MECHANISM_DKIM,
    MECHANISM_SPF,
    EffectiveAuthPolicy,
    EmailAuthResult,
    resolve_auth_policy,
    validate_email_auth,
)
from fastsmtp.storage.raw_message import RawMessagePreserver, should_preserve_raw
from fastsmtp.storage.s3 import sanitize_key_component

logger = logging.getLogger(__name__)


def key_safe_message_id(raw_message_id: str | None) -> str:
    """Return a Message-ID usable as an S3 key component, generating one if not.

    Both S3 key paths -- the raw archive (``_build_raw_key``) and the attachment
    prefix (``_build_key``) -- run the Message-ID through
    ``sanitize_key_component``, whose fallback is a single shared literal. So a
    header that is present but degenerate (``<>``, ``<  >``, ``""``) is truthy,
    survives a "did we get one?" check, and *then* collapses to that literal --
    putting every such message at the same key, where S3's last-write-wins
    silently destroys the previous one.

    That is invisible under ``preserve_raw_required``, whose promise is "the
    archive exists or the transaction rolls back": an overwrite is a *successful*
    PUT, so the promise is kept while the data is gone.

    Testing truthiness is therefore not enough -- the question is whether
    anything survives sanitisation.
    """
    if raw_message_id and sanitize_key_component(raw_message_id, fallback=""):
        return raw_message_id
    return f"<{uuid.uuid4()}@fastsmtp>"


def address_domain(address: str) -> str | None:
    """Lowercased domain part of an email address, or None if it has none."""
    if "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower()


def encoded_domain_name(domain_name: str) -> str | None:
    """A domain part spelled the way the ``domains`` table stores it.

    International domain names are normalised to ASCII punycode, so
    ``example.com`` and its Cyrillic lookalike are different rows. None when
    idna rejects the name, which no configured domain can match either.

    Every path that resolves a domain from a recipient address goes through
    this, so the receive-time policy lookup and :func:`lookup_recipient`
    cannot disagree about which row an address belongs to.

    ``IDNAError`` is the base of everything idna raises, and catching only the
    codepoint subclasses left the rest -- an empty domain, an empty label
    (``a..b``), a leading hyphen, an over-long label -- propagating out of a
    recipient lookup as an unhandled exception.
    """
    try:
        return idna.encode(domain_name.lower()).decode("ascii")
    except idna.IDNAError:
        return None


def select_live_domain(domain_name: str) -> Select[tuple[Domain]]:
    """Select the live, enabled domain owning ``domain_name`` (already encoded).

    The single predicate deciding whether a domain exists for incoming mail.
    Shared so no caller can accept mail for a domain another caller would
    consider gone.
    """
    return select(Domain).where(
        Domain.domain_name == domain_name,
        Domain.is_enabled.is_(True),
        Domain.live(),
    )


async def load_domain_for_policy(session: AsyncSession, domain_name: str) -> Domain | None:
    """Load the domain a recipient's auth policy comes from, and nothing else.

    ``lookup_recipient`` answers the same question but ``selectinload``s the
    domain's entire recipients collection, which resolving a policy has no use
    for: it reads four booleans off the domain row. Same predicate, one query,
    no collection.
    """
    result = await session.execute(select_live_domain(domain_name))
    return result.scalar_one_or_none()


@dataclass(frozen=True)
class RecipientAuthPolicy:
    """One envelope recipient paired with the auth policy of its domain.

    The address itself is not kept: a refusal now decides the whole message,
    so what a reply and a log line need is the domain that refused it, not
    which of its addresses the envelope named.
    """

    domain_name: str
    """The domain the policy came from; the address's own domain if none resolved."""
    policy: EffectiveAuthPolicy


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

    local_part, raw_domain_name = address.rsplit("@", 1)
    local_part_lower = local_part.lower()

    domain_name = encoded_domain_name(raw_domain_name)
    if domain_name is None:
        return None, None, "Invalid domain name encoding"

    # Look up domain with recipients (excluding soft-deleted)
    stmt = select_live_domain(domain_name).options(selectinload(Domain.recipients))
    result = await session.execute(stmt)
    domain = result.scalar_one_or_none()

    if not domain:
        return None, None, f"Domain {domain_name} not configured"

    # Find matching recipient: exact match first, then subaddress (plus-tag)
    # base match, then catch-all. Filter out disabled and soft-deleted recipients.
    active_recipients = [r for r in domain.recipients if r.is_enabled and not r.is_deleted]

    def find_specific(target_local_part: str) -> Recipient | None:
        for recipient in active_recipients:
            if recipient.local_part is None:
                continue
            if recipient.local_part.lower() == target_local_part:
                return recipient
        return None

    specific_recipient = find_specific(local_part_lower)

    # Subaddress fallback: support+TICKET-123@example.com routes to "support"
    if specific_recipient is None and "+" in local_part_lower:
        specific_recipient = find_specific(local_part_lower.split("+", 1)[0])

    catchall_recipient = next((r for r in active_recipients if r.local_part is None), None)

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

        # S3 storage client, shared by attachment offloading and raw message
        # preservation. Raw preservation is enabled per domain and per rule, so
        # the client is built whenever credentials exist, not only when
        # attachment_storage == "s3".
        self._s3_storage = None
        if self.settings.s3_configured:
            try:
                from fastsmtp.storage.s3 import S3Storage

                self._s3_storage = S3Storage(self.settings)
                logger.info("S3 storage initialized")
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

        With recipients on several domains the strictest policy wins: if any
        one of them refuses the message on a failed DKIM or SPF check, the
        whole message is refused. Accepting for the others would mean
        answering 250 and then discarding the message for the refusing
        addresses - and after a 250 this server owns the delivery or must
        bounce it itself, so a silent discard is mail loss. The 550 hands the
        decision back to the sending MTA, which bounces to a human who can see
        it and can resend to the lenient address alone.
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

        # Get Message-ID (use UUID if unusable, for reliable deduplication)
        message_id = key_safe_message_id(message.get("Message-ID"))

        # Each recipient domain decides which checks apply to its own mail, so
        # the recipients have to be resolved before anything is verified. This
        # lookup selects policy only: _process_and_persist_message re-resolves
        # every address inside its own transaction and remains the one liveness
        # decision for a recipient.
        try:
            rcpt_policies = await self._resolve_recipient_policies(envelope.rcpt_tos)
        except Exception as e:
            logger.exception(f"Failed to resolve recipients for message {message_id}: {e}")
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return "451 Temporary failure, please retry"

        # A mechanism is verified once for the message if any recipient domain
        # asks for it; recipients that did not ask simply ignore the result.
        auth_result = await validate_email_auth(
            message=content,
            client_ip=client_ip,
            mail_from=mail_from,
            helo=helo,
            verify_dkim_enabled=any(entry.policy.verify_dkim for entry in rcpt_policies),
            verify_spf_enabled=any(entry.policy.verify_spf for entry in rcpt_policies),
        )

        logger.info(
            f"Message {message_id}: DKIM={auth_result.dkim_result}, SPF={auth_result.spf_result}"
        )

        # Record authentication metrics
        AUTH_RESULTS.labels(type="dkim", result=auth_result.dkim_result).inc()
        AUTH_RESULTS.labels(type="spf", result=auth_result.spf_result).inc()

        # Rejection is per recipient domain: a domain rejects on a mechanism
        # only if it both verifies it and asked for failures to be rejected.
        # One domain refusing refuses the message for every recipient - see
        # the docstring for why a partial acceptance is not on offer.
        refusals = [
            (entry, refused_on)
            for entry in rcpt_policies
            if (refused_on := entry.policy.refused_mechanism(auth_result)) is not None
        ]

        if refusals:
            # Refusals that mix mechanisms report DKIM: it is the stricter
            # signal (the message was signed and the signature did not hold),
            # and a message failing both keeps the reply it always had.
            mechanism = (
                MECHANISM_DKIM if any(m == MECHANISM_DKIM for _, m in refusals) else MECHANISM_SPF
            )
            refused_by = ", ".join(sorted({entry.domain_name for entry, _ in refusals}))
            logger.warning(
                f"Rejecting message {message_id}: {mechanism} failed, refused by {refused_by}"
            )
            SMTP_MESSAGES_TOTAL.labels(result="rejected").inc()
            return f"550 {mechanism} verification failed"

        # Process message and persist to database BEFORE returning 250 OK
        # This ensures no data loss if the server crashes
        try:
            deliveries_created = await self._process_and_persist_message(
                envelope=envelope,
                message=message,
                message_id=message_id,
                auth_result=auth_result,
                client_ip=client_ip,
                raw_content=content,
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

    async def _resolve_recipient_policies(self, rcpt_tos: list[str]) -> list[RecipientAuthPolicy]:
        """Pair every envelope recipient with the auth policy of its domain.

        An address that resolves to no configured domain keeps the global
        policy: it is judged exactly as it was before domains could override
        anything, and the delivery path skips it either way.

        The result is never empty. aiosmtpd refuses DATA without a RCPT, so an
        empty envelope should not reach here, but if one does the global policy
        still decides the message rather than nothing verifying it.
        """
        if not rcpt_tos:
            return [
                RecipientAuthPolicy(
                    # Nothing to name in a refusal log line; say so rather
                    # than leaving it blank.
                    domain_name="(no recipients)",
                    policy=resolve_auth_policy(None, self.settings),
                )
            ]

        policies: list[RecipientAuthPolicy] = []
        # The policy is a property of the domain, so recipients that share one
        # need only one query.
        by_domain_part: dict[str | None, Domain | None] = {}
        async with async_session() as db_session:
            for rcpt_to in rcpt_tos:
                domain_part = address_domain(rcpt_to)
                if domain_part not in by_domain_part:
                    lookup_name = encoded_domain_name(domain_part) if domain_part else None
                    found = None
                    if lookup_name is not None:
                        found = await load_domain_for_policy(db_session, lookup_name)
                    by_domain_part[domain_part] = found
                domain = by_domain_part[domain_part]
                policies.append(
                    RecipientAuthPolicy(
                        domain_name=domain.domain_name if domain else (domain_part or rcpt_to),
                        policy=resolve_auth_policy(domain, self.settings),
                    )
                )

        return policies

    async def _process_and_persist_message(
        self,
        envelope: Envelope,
        message: Message,
        message_id: str,
        auth_result: EmailAuthResult,
        client_ip: str,
        raw_content: bytes,
    ) -> int:
        """Process message for each recipient and persist deliveries to database.

        Every recipient here is one the message was accepted for: a domain
        that refuses it refuses it for everyone, in handle_DATA, before any of
        this runs.

        Args:
            envelope: SMTP envelope
            message: Parsed email message
            message_id: Message-ID header value
            auth_result: Email authentication result, as computed for the
                message. Each recipient sees only the mechanisms its own
                domain verifies (:meth:`EffectiveAuthPolicy.masked`)
            client_ip: Client IP address
            raw_content: Complete raw MIME message as received

        Returns:
            Number of deliveries created
        """
        # Import here to avoid circular import
        from fastsmtp.rules.engine import evaluate_rules
        from fastsmtp.webhook.queue import enqueue_delivery

        # Determine domain for S3 storage key (use first recipient's domain)
        recipient_domain = address_domain(envelope.rcpt_tos[0]) if envelope.rcpt_tos else None

        # Attachment offloading stays gated on attachment_storage
        s3_storage = None
        if self.settings.attachment_storage == "s3":
            s3_storage = self._s3_storage

        # Raw preservation uploads the same bytes for every recipient, so it
        # runs at most once and only if some recipient actually asks for it
        raw_preserver = RawMessagePreserver(
            content=raw_content,
            message_id=message_id,
            s3_storage=self._s3_storage,
            settings=self.settings,
            received_at=datetime.now(UTC),
        )

        # Extract base payload (same for all recipients)
        base_payload = await extract_email_payload(
            message,
            envelope,
            self.settings,
            s3_storage=s3_storage,
            domain=recipient_domain,
            message_id=message_id,
        )
        base_payload["client_ip"] = client_ip

        deliveries_created = 0

        async with async_session() as db_session:
            # Process each recipient
            for rcpt_to in envelope.rcpt_tos:
                domain, recipient, error = await lookup_recipient(rcpt_to, db_session)

                if error or not domain or not recipient:
                    logger.warning(f"Message {message_id}: skipping recipient {rcpt_to}: {error}")
                    continue

                # A mechanism runs for the message as soon as one recipient
                # domain asks for it, so blank out the ones this domain did
                # not: its rules, its payload and its delivery log must not
                # carry a decision it opted out of.
                recipient_auth = resolve_auth_policy(domain, self.settings).masked(auth_result)
                payload = base_payload.copy()
                payload["dkim_result"] = recipient_auth.dkim_result
                payload["dkim_domain"] = recipient_auth.dkim_domain
                payload["spf_result"] = recipient_auth.spf_result
                payload["spf_domain"] = recipient_auth.spf_domain

                # Evaluate the rules of the domain the lookup just accepted the
                # message for. That lookup is the one liveness decision for
                # this recipient; the engine takes the row rather than the id
                # so it cannot make a second, possibly different, one.
                rule_result = await evaluate_rules(
                    session=db_session,
                    domain=domain,
                    message=message,
                    payload=payload,
                    auth_result=recipient_auth,
                )

                # Archive before honouring a drop so a rule can preserve and discard
                raw_info = None
                if should_preserve_raw(domain, rule_result.preserve_raw, self.settings):
                    raw_info = await raw_preserver.preserve(domain.domain_name)

                # Check if message should be dropped
                if rule_result.should_drop:
                    logger.info(f"Message {message_id}: dropped for {rcpt_to} by rules")
                    continue

                # Finish the recipient-specific payload
                payload["tags"] = rule_result.tags
                payload["recipient"] = rcpt_to
                if raw_info is not None:
                    payload["raw_message"] = RawMessagePreserver.payload_block(raw_info)

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
                    auth_result=recipient_auth,
                    settings=self.settings,
                )
                deliveries_created += 1

            # Commit all deliveries in a single transaction
            await db_session.commit()

        return deliveries_created


class _PartInfo(NamedTuple):
    """How a MIME part should be represented in the webhook payload.

    ``disposition`` is ``None`` when the part is body text and belongs in
    ``body_text`` or ``body_html``.
    """

    disposition: str | None
    filename: str | None
    content_id: str | None


# A Content-ID is an addr-spec (RFC 2045), so none of these can appear in a
# well-formed one. The value is sender-controlled and consumers interpolate it
# into HTML to resolve cid: references, so a malformed one is dropped rather
# than forwarded.
_UNSAFE_CONTENT_ID_CHARS = re.compile(r"""[\x00-\x1f\x7f<>"'\s]""")
_MAX_CONTENT_ID_LENGTH = 512

# Matches the cid: URLs in an HTML body, including the CSS url(cid:...) form.
_CID_REFERENCE = re.compile(r"""cid:([^"'\s>)]+)""", re.IGNORECASE)


def _content_id_value(part: Message) -> str | None:
    """Return a part's Content-ID as the bare addr-spec, or ``None``.

    The header value is wrapped in angle brackets while the ``cid:`` URL in the
    HTML body is the bare addr-spec (RFC 2392). Consumers match against the
    URL, so strip the brackets here rather than making every one of them do it.
    A bare ``Content-ID: <>``, which some relays emit, reduces to ``None``.
    """
    raw = part.get("Content-ID")
    if not raw:
        return None
    value = str(raw).strip().lstrip("<").rstrip(">").strip()
    if not value or len(value) > _MAX_CONTENT_ID_LENGTH:
        return None
    if _UNSAFE_CONTENT_ID_CHARS.search(value):
        return None
    return value


def _counts_as_attachment(attachment: dict[str, Any], referenced: set[str]) -> bool:
    """Whether a captured part should set ``has_attachments``.

    Only parts the HTML body actually renders are excused - a ``cid:`` URL
    pointing at this part's Content-ID. A part is not excused for merely
    saying ``inline``, or for declaring a Content-ID nothing references:
    either would let a sender deliver a file to the webhook consumer while
    ``has_attachment`` rules stayed silent.

    An ``attachment`` disposition always counts, referenced or not. Outlook
    marks cid images that way, and those set the flag today.
    """
    if attachment.get("disposition") == "attachment":
        return True
    content_id = attachment.get("content_id")
    return content_id is None or content_id not in referenced


def _classify_part(part: Message) -> _PartInfo:
    """Decide whether a MIME part is an attachment, an inline part, or body.

    The distinction cannot be read off Content-Disposition alone: Outlook and
    Apple Mail both mark the body parts themselves ``inline``. What separates
    an inline *file* from the body is a filename.

    A Content-ID deliberately does not: RFC 2387 identifies the root part of a
    ``multipart/related`` by the container's ``start`` parameter, whose value
    is that part's Content-ID, so an HTML body legitimately carries the header.
    Treating it as a file marker empties ``body_html`` for that mail.
    """
    filename = part.get_filename()
    content_id = _content_id_value(part)
    disposition = (part.get("Content-Disposition") or "").split(";")[0].strip().lower()

    if disposition == "attachment":
        return _PartInfo("attachment", filename, content_id)

    if part.get_content_maintype() == "text" and not filename:
        return _PartInfo(None, filename, content_id)

    if disposition == "inline" or content_id:
        return _PartInfo("inline", filename, content_id)
    if filename:
        # No disposition header at all, but a name= on the Content-Type. Some
        # clients emit exactly that for a genuine attachment.
        return _PartInfo("attachment", filename, content_id)
    if part.get_content_maintype() == "message":
        # An attached message/rfc822 (a forwarded email) with no disposition,
        # Content-ID or filename of its own - unlike a bare text part, this is
        # never body content. Falling through to None here would drop the
        # entire forwarded message with no trace at all.
        return _PartInfo("attachment", filename, content_id)
    return _PartInfo(None, filename, content_id)


def _fallback_filename(content_type: str, index: int) -> str:
    """Name a part that carries no filename of its own.

    cid-referenced images routinely have only a Content-ID. Naming every one of
    them the same literal would be invisible in the payload but not in S3,
    where the key is built from the filename: two nameless parts in one message
    would write to one key and the second would overwrite the first.
    """
    extension = mimetypes.guess_extension(content_type) or ""
    return f"part-{index}{extension}"


def _iter_payload_parts(message: Message) -> Iterator[Message]:
    """Yield the parts of ``message`` that belong in the webhook payload.

    Mirrors ``Message.walk()`` for ordinary ``multipart/*`` containers, but
    treats an attached ``message/rfc822`` part as a single leaf instead of
    recursing into the forwarded message's own parts.

    ``Message.walk()`` does not make that distinction: a message/rfc822 part
    is internally shaped like a multipart one (its payload is a one-element
    list holding the forwarded ``Message``), which is enough to make
    ``is_multipart()`` true and pull ``walk()`` into it. That let a forwarded
    message's body overwrite the outer body and its attachments hoist into
    the outer attachment list - see issue #148. Checking the maintype instead
    of ``is_multipart()`` is what keeps the two apart: only an actual
    ``multipart/*`` container has maintype ``"multipart"``.
    """
    if message.get_content_maintype() != "multipart":
        yield message
        return

    payload = message.get_payload()
    if not isinstance(payload, list):
        # A multipart the parser could not split - one declaring no boundary,
        # say - keeps its raw payload as a string and has no parts to yield.
        return
    # Every element of a split multipart payload is a Message by construction.
    for subpart in cast(list[Message], payload):
        yield from _iter_payload_parts(subpart)


def _attached_message_bytes(part: Message) -> bytes | None:
    """Serialize an attached message part back into its .eml bytes.

    Covers ``message/global`` (RFC 6532's UTF-8 variant) on the same terms;
    anything else under ``message/*``, such as a multi-block
    ``message/delivery-status``, fails the single-submessage guard below and
    keeps the metadata-only entry it has today.

    ``get_payload(decode=True)`` returns ``None`` for a message/rfc822 part -
    it is internally shaped like a multipart payload (a one-element list
    holding the forwarded ``Message``), and decode=True bails out on any
    multipart payload. Serializing that submessage is what actually recovers
    the forwarded email's bytes, so the attachment carries real content
    instead of the ``size: 0`` stub it used to.

    A forward-of-a-forward-of-a-forward, nested deeply enough, blows Python's
    recursion limit during serialization even though parsing it succeeded -
    each level of message/rfc822 nesting costs multiple stack frames in the
    generator. Degrading that one attachment to the pre-fix "no content" stub
    keeps a single crafted message from failing delivery outright.
    """
    payload = part.get_payload()
    if not (isinstance(payload, list) and len(payload) == 1 and isinstance(payload[0], Message)):
        return None
    try:
        return payload[0].as_bytes()
    except Exception as e:
        logger.warning(f"Failed to serialize message/rfc822 attachment, using metadata only: {e}")
        return None


async def extract_email_payload(
    message: Message,
    envelope: Envelope,
    settings: Settings | None = None,
    s3_storage: "S3Storage | None" = None,
    domain: str | None = None,
    message_id: str | None = None,
) -> dict:
    """Extract email content into a webhook payload.

    Args:
        message: Parsed email message
        envelope: SMTP envelope
        settings: Application settings (for attachment size limits)
        s3_storage: S3 storage client (if S3 enabled)
        domain: Email domain for S3 key path
        message_id: Message ID for the S3 key path; falls back to the
            Message-ID header, then a generated UUID, so messages without a
            usable Message-ID never share (and overwrite) the same S3 key prefix
    """
    s3_message_id = key_safe_message_id(message_id or message.get("Message-ID"))
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
    nameless_parts = 0
    body_text = ""
    body_html = ""

    if message.is_multipart():
        for part in _iter_payload_parts(message):
            content_type = part.get_content_type()
            disposition, part_filename, content_id = _classify_part(part)

            if disposition is not None:
                # Handle attachment or inline part
                if part_filename:
                    filename = part_filename
                else:
                    nameless_parts += 1
                    filename = _fallback_filename(content_type, nameless_parts)
                part_payload = part.get_payload(decode=True)
                if part_payload is None and part.get_content_maintype() == "message":
                    part_payload = _attached_message_bytes(part)
                size = len(part_payload) if isinstance(part_payload, bytes) else 0

                attachment_info: dict[str, Any] = {
                    "filename": filename,
                    "content_type": content_type,
                    "size": size,
                    "disposition": disposition,
                }
                if content_id:
                    attachment_info["content_id"] = content_id

                if isinstance(part_payload, bytes) and s3_storage and domain:
                    # Upload to S3
                    try:
                        s3_info = await s3_storage.upload_attachment(
                            content=part_payload,
                            domain=domain,
                            message_id=s3_message_id,
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
    # This field backs the "has_attachment" rule condition. Inline signature
    # logos ride on a large share of ordinary mail, so counting every captured
    # part would silently re-route existing rules the first time a message
    # carried a footer image - but only the ones the body actually renders are
    # excused. See _counts_as_attachment.
    referenced = {match.group(1) for match in _CID_REFERENCE.finditer(body_html)}
    payload["has_attachments"] = any(_counts_as_attachment(a, referenced) for a in attachments)

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


# RFC 4954 AUTH parameter on MAIL FROM: "AUTH=" followed by <>, <address>,
# or an xtext token; never contains whitespace.
_MAIL_AUTH_PARAM_RE = re.compile(r"\sAUTH=\S+", re.IGNORECASE)


class AuthParamTolerantSMTP(SMTP):
    """SMTP session that accepts and ignores the AUTH parameter on MAIL FROM.

    Once AUTH is advertised in EHLO, RFC 4954 section 5 lets clients add
    AUTH=<...> to MAIL FROM (Exchange Online always does) and lets the server
    "treat the AUTH parameter as if it had not been supplied". aiosmtpd
    replies 555 to any parameter it does not implement, so strip AUTH from
    the argument before delegating.
    """

    @syntax("MAIL FROM: <address>", extended=" [SP <mail-parameters>]")
    async def smtp_MAIL(self, arg: str | None) -> None:
        if arg:
            # Parameters follow the bracketed address; leave the address alone
            addr_end = arg.find(">")
            if addr_end != -1:
                arg = arg[: addr_end + 1] + _MAIL_AUTH_PARAM_RE.sub("", arg[addr_end + 1 :])
        await super().smtp_MAIL(arg)


class FastSMTPController(UnthreadedController):
    """UnthreadedController that serves AuthParamTolerantSMTP sessions."""

    def factory(self) -> SMTP:
        return AuthParamTolerantSMTP(self.handler, **self.SMTP_kwargs)


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
        self.controller: FastSMTPController | None = None
        self.tls_controller: FastSMTPController | None = None
        self._server: asyncio.AbstractServer | None = None
        self._tls_server: asyncio.AbstractServer | None = None
        self._tls_manager: TLSContextManager | None = None
        self._hot_reload_task: asyncio.Task | None = None

    @staticmethod
    def _bound_port(server: asyncio.AbstractServer | None, name: str) -> int:
        # loop.create_server() always returns an asyncio.Server; the isinstance
        # check narrows from the AbstractServer the aiosmtpd controller is
        # annotated with, which lacks ``sockets``.
        if server is None or not isinstance(server, asyncio.Server) or not server.sockets:
            raise RuntimeError(f"{name} is not started; no socket is bound yet")
        port = server.sockets[0].getsockname()[1]
        return int(port)

    @property
    def bound_smtp_port(self) -> int:
        """Port the plain SMTP listener is actually bound to.

        ``settings.smtp_port`` is only the *requested* port: with
        ``smtp_port=0`` the OS assigns a free port at bind time and the bound
        socket is the sole source of truth (aiosmtpd's controller keeps just
        the requested value). Raises ``RuntimeError`` until :meth:`start` has
        run.
        """
        return self._bound_port(self._server, "SMTP server")

    @property
    def bound_smtp_tls_port(self) -> int:
        """Port the implicit-TLS listener is actually bound to.

        Same contract as :attr:`bound_smtp_port` for the TLS listener. Raises
        ``RuntimeError`` until :meth:`start` has run with TLS configured.
        """
        return self._bound_port(self._tls_server, "SMTP TLS server")

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
        self.tls_controller = FastSMTPController(
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

        # Load TLS context first (needed for both STARTTLS and implicit TLS)
        self._tls_manager = TLSContextManager(self.settings)
        tls_context = self._tls_manager.load_context()

        # Build kwargs for plain SMTP server
        plain_smtp_kwargs: dict = {
            "data_size_limit": self.settings.smtp_max_message_size,
        }

        # Enable STARTTLS on plain port if TLS is configured
        if tls_context:
            plain_smtp_kwargs["tls_context"] = tls_context
            if self.settings.smtp_require_starttls:
                plain_smtp_kwargs["require_starttls"] = True

        # Start plain SMTP server using UnthreadedController
        self.controller = FastSMTPController(
            self.handler,
            hostname=self.settings.smtp_host,
            port=self.settings.smtp_port,
            loop=loop,
            **plain_smtp_kwargs,
        )
        # Await _create_server() directly instead of calling begin()
        # This properly integrates with the running event loop
        self._server = await self.controller._create_server()

        max_size_mb = self.settings.smtp_max_message_size / (1024 * 1024)
        starttls_status = ""
        if tls_context:
            if self.settings.smtp_require_starttls:
                starttls_status = ", STARTTLS required"
            else:
                starttls_status = ", STARTTLS available"
        logger.info(
            f"SMTP server started on {self.settings.smtp_host}:{self.settings.smtp_port} "
            f"(max message size: {max_size_mb:.1f}MB{starttls_status})"
        )

        # Start implicit TLS SMTP server if configured (port 465)
        if tls_context:
            self.tls_controller = FastSMTPController(
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
                f"{self.settings.smtp_host}:{self.settings.smtp_tls_port} (implicit TLS)"
            )

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
