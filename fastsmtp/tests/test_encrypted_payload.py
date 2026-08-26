"""Storage-layer tests for ``delivery_log.payload`` under EncryptedJSON.

``test_encrypted_types.py`` proves what the ``EncryptedJSON`` type does. This
file proves what happens when *this* column adopts it, which is a different set
of claims: the payload is the message itself - subject, bodies and inline
base64 attachments - kept for the retention window, and three separate readers
have to keep seeing it exactly as they did before.

The claims under test:

* **``payload_hash`` is still a hash of the plaintext.** ``compute_payload_hash``
  runs in ``enqueue_delivery`` before the row is flushed and the column type
  encrypts on the way to the database, so the ordering has to hold. Hashing
  Fernet output would give a value that differs on every encryption of the same
  message and would silently stop being a content fingerprint - while still
  looking like a hex digest in the delivery-log list API.
* **Nothing above the storage layer changes.** The dispatcher posts the payload
  as the webhook body, ``GET /delivery-log/{id}`` returns it in full, and the
  retry path re-sends what is stored. All three must see the plaintext dict.
* **Rows are written once.** There is no update path for a payload, and the
  decision on this column was to let retention age plaintext rows out rather
  than backfill them. So a legacy plaintext row stays readable and stays
  plaintext: no read, claim, failure, retry or delivery converts it.
* **An undecryptable payload raises.** A worker that degraded to ``{}`` would
  POST an empty body, take a 2xx for it and mark the message delivered.

Every storage claim is checked against the raw cell with a SQL cast to text,
which comes back through ``Text``'s result processor and so never runs
``EncryptedJSON.process_result_value``. A round trip through the ORM proves
nothing about what is on disk - it would pass with the decorator deleted.
"""

import base64
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from unittest.mock import patch

import httpx
import pytest
from fastsmtp.config import Settings
from fastsmtp.crypto import ENVELOPE_MARKER, DecryptionError, is_encrypted
from fastsmtp.db.enums import DeliveryStatus
from fastsmtp.db.models import DeliveryLog, Domain, Recipient
from fastsmtp.webhook.dispatcher import process_delivery
from fastsmtp.webhook.queue import (
    compute_payload_hash,
    enqueue_delivery,
    get_pending_deliveries,
    mark_delivered,
    mark_failed,
    retry_delivery,
)
from httpx import AsyncClient
from sqlalchemy import Dialect, Text, cast, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.schema import CreateTable

#: Two unrelated operator keys. Deriving one costs 100k PBKDF2 iterations and
#: ``get_cipher`` memoizes per key tuple, so this file uses as few as possible.
KEY_A = "payload-key-alpha"
KEY_B = "payload-key-bravo"

WEBHOOK_URL = "https://hooks.example.com/inbound"

#: The strings that must not appear on disk once a key is configured: a
#: subject, a body, an address and the bytes of an inline attachment.
SUBJECT = "Q3 numbers before the announcement"
BODY_TEXT = "Revenue came in at 41.2M, do not forward this."
SENDER = "cfo@external.com"
ATTACHMENT = "JVBERi0xLjQKJSDi48"
SECRETS = (SUBJECT, BODY_TEXT, SENDER, ATTACHMENT)

#: A payload shaped like a real one.
PAYLOAD = {
    "message_id": "<confidential@external.com>",
    "sender": SENDER,
    "recipient": "board@customer.example.com",
    "subject": SUBJECT,
    "body_text": BODY_TEXT,
    "body_html": f"<p>{BODY_TEXT}</p>",
    "attachments": [{"filename": "q3.pdf", "content": ATTACHMENT}],
}


@dataclass
class Route:
    """A domain and one recipient, the two rows a delivery needs to exist."""

    domain_id: uuid.UUID
    recipient_id: uuid.UUID


async def seed_route(session: AsyncSession) -> Route:
    """Insert a live domain and recipient and return their ids.

    Both must be live or the claim query and the dispatcher guard will refuse
    the delivery before any payload is read.
    """
    domain = Domain(domain_name=f"{uuid.uuid4().hex[:12]}.example.com", is_enabled=True)
    session.add(domain)
    await session.flush()

    recipient = Recipient(
        domain_id=domain.id,
        local_part="board",
        webhook_url=WEBHOOK_URL,
        is_enabled=True,
    )
    session.add(recipient)
    await session.commit()
    return Route(domain_id=domain.id, recipient_id=recipient.id)


async def enqueue(
    session: AsyncSession,
    route: Route,
    payload: dict,
    settings: Settings,
    *,
    message_id: str = "<queued@external.com>",
) -> uuid.UUID:
    """Enqueue through the real production path and return the delivery id.

    ``enqueue_delivery`` is what computes ``payload_hash`` and what a test of
    the hash/encryption ordering has to exercise; constructing a ``DeliveryLog``
    by hand would assert the test's own ordering instead.
    """
    delivery = await enqueue_delivery(
        session=session,
        domain_id=route.domain_id,
        recipient_id=route.recipient_id,
        message_id=message_id,
        webhook_url=WEBHOOK_URL,
        payload=payload,
        settings=settings,
    )
    await session.commit()
    return delivery.id


async def raw_cell(session: AsyncSession, delivery_id: uuid.UUID) -> str:
    """The payload cell exactly as the database holds it.

    Casting in SQL is the whole point: the value returns through ``Text``'s
    result processor, so ``EncryptedJSON`` never sees it and nothing decrypts
    it on the way out.
    """
    stmt = select(cast(DeliveryLog.payload, Text)).where(DeliveryLog.id == delivery_id)
    return (await session.execute(stmt)).scalar_one()


async def load_payload(factory: async_sessionmaker[AsyncSession], delivery_id: uuid.UUID) -> dict:
    """Read the delivery back through the ORM in a session of its own.

    A fresh session means a real SELECT and a real trip through the type's
    result processing, not an identity-map hit on the object just written.
    """
    async with factory() as session:
        delivery = await session.get_one(DeliveryLog, delivery_id)
        return delivery.payload


async def claim_one(
    factory: async_sessionmaker[AsyncSession], delivery_id: uuid.UUID
) -> tuple[AsyncSession, DeliveryLog]:
    """Claim a delivery exactly as the worker does, and hand back its session.

    ``get_pending_deliveries`` is the only path that loads a delivery for
    dispatch: it eager-loads the recipient (``lazy="raise"``) and locks the row.
    The session stays open because the caller goes on to dispatch in it.
    """
    session = factory()
    claimed = await get_pending_deliveries(session, batch_size=10)
    matching = [d for d in claimed if d.id == delivery_id]
    assert len(matching) == 1, f"expected to claim {delivery_id}, claimed {[d.id for d in claimed]}"
    return session, matching[0]


async def dispatch(
    session: AsyncSession, delivery: DeliveryLog, settings: Settings
) -> httpx.Request:
    """Run the real dispatcher against a mock transport; return what went out.

    A ``MockTransport`` rather than a patched ``send_webhook`` so the assertion
    is over the bytes on the wire: what a customer's endpoint would receive.
    """
    sent: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        # The URL never resolves; SSRF validation is not what is under test.
        with patch("fastsmtp.webhook.dispatcher.validate_webhook_url"):
            await process_delivery(delivery, settings, session, client=client)

    assert len(sent) == 1, f"expected one webhook request, got {len(sent)}"
    return sent[0]


def column_ddl(dialect: Dialect) -> str:
    """The payload line of CREATE TABLE delivery_log, for one dialect."""
    ddl = str(CreateTable(DeliveryLog.__table__).compile(dialect=dialect))
    lines = [
        line.strip().rstrip(",") for line in ddl.splitlines() if line.strip().startswith("payload ")
    ]
    assert len(lines) == 1, f"expected one payload column, got {lines}"
    return lines[0]


async def test_payload_hash_is_a_hash_of_the_plaintext(
    session_factory: async_sessionmaker[AsyncSession],
    auth_client: AsyncClient,
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test the same message enqueued twice keeps one hash and gets two ciphertexts.

    This is the ordering ``enqueue_delivery`` depends on: the hash is taken from
    the dict before the flush, and the column type encrypts on the way to the
    database. Fernet output is non-deterministic, so if the hash were ever
    computed from the stored form the two rows below would disagree - and
    ``payload_hash`` would still look like a digest to every caller of the
    delivery-log list API while having stopped being a content fingerprint.
    """
    configure_keys(KEY_A)
    expected = compute_payload_hash(PAYLOAD)

    async with session_factory() as session:
        route = await seed_route(session)
        first = await enqueue(session, route, PAYLOAD, test_settings, message_id="<one@ext.com>")
        second = await enqueue(session, route, PAYLOAD, test_settings, message_id="<two@ext.com>")
        raw_first = await raw_cell(session, first)
        raw_second = await raw_cell(session, second)

    # The fingerprint is the same message twice, so it must be one value.
    async with session_factory() as session:
        hashes = {
            row.id: row.payload_hash
            for row in (await session.execute(select(DeliveryLog))).scalars()
        }
    assert hashes[first] == hashes[second] == expected

    # ...and yet no two encryptions of it are alike.
    assert is_encrypted(json.loads(raw_first))
    assert is_encrypted(json.loads(raw_second))
    assert raw_first != raw_second

    # The decisive check: hashing what is actually stored gives something else,
    # so the recorded hash cannot have been taken from the ciphertext.
    assert compute_payload_hash(json.loads(raw_first)) != expected
    assert compute_payload_hash(json.loads(raw_second)) != expected

    # The list API still hands both rows the same usable fingerprint.
    response = await auth_client.get(f"/api/v1/domains/{route.domain_id}/delivery-log")
    assert response.status_code == 200
    listed = {row["id"]: row["payload_hash"] for row in response.json()}
    assert listed[str(first)] == listed[str(second)] == expected


async def test_no_key_stores_the_payload_in_clear(
    session_factory: async_sessionmaker[AsyncSession],
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test the column is a pass-through until a key is configured.

    This is the default and the state of every deployment that has not opted
    in, so it has to be byte-for-byte the plain JSON column it replaced.
    """
    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, PAYLOAD, test_settings)
        stored = json.loads(await raw_cell(session, delivery_id))

    assert stored == PAYLOAD
    assert not is_encrypted(stored)
    assert ENVELOPE_MARKER not in stored
    assert await load_payload(session_factory, delivery_id) == PAYLOAD


async def test_key_leaves_no_message_content_on_disk(
    session_factory: async_sessionmaker[AsyncSession],
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test a configured key puts an envelope on disk and nothing readable.

    The whole point of this column: a stolen dump or backup holds the message
    bodies of the retention window unless this holds.
    """
    configure_keys(KEY_A)

    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, PAYLOAD, test_settings)
        raw = await raw_cell(session, delivery_id)

    stored = json.loads(raw)
    assert is_encrypted(stored)
    assert stored[ENVELOPE_MARKER] == 1
    assert isinstance(stored["ciphertext"], str)
    for secret in SECRETS:
        assert secret not in raw

    # ...and the application above the storage layer sees none of that.
    assert await load_payload(session_factory, delivery_id) == PAYLOAD


async def test_dispatcher_posts_the_plaintext_payload(
    session_factory: async_sessionmaker[AsyncSession],
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test the webhook body is the payload the sender enqueued.

    The first of the three readers. The dispatcher takes ``delivery.payload``
    straight from the claimed row and posts it as JSON, so an envelope reaching
    this far would be delivered to the customer's endpoint as the message.
    """
    configure_keys(KEY_A)

    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, PAYLOAD, test_settings)
        assert is_encrypted(json.loads(await raw_cell(session, delivery_id)))

    session, claimed = await claim_one(session_factory, delivery_id)
    async with session:
        request = await dispatch(session, claimed, test_settings)
        await session.commit()

    assert json.loads(request.content) == PAYLOAD

    async with session_factory() as session:
        delivered = await session.get_one(DeliveryLog, delivery_id)
        assert delivered.status == DeliveryStatus.DELIVERED
        # Marking it delivered did not rewrite the payload into plaintext.
        assert is_encrypted(json.loads(await raw_cell(session, delivery_id)))


async def test_detail_route_returns_what_it_returned_before(
    session_factory: async_sessionmaker[AsyncSession],
    auth_client: AsyncClient,
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test GET /delivery-log/{id} is unchanged by encryption.

    The second reader, and the one an operator sees. The decision on this issue
    was explicit that API responses and payload shapes do not change, so the
    test is a comparison rather than an assertion about one row: the same
    message stored in clear and stored encrypted must produce the same JSON.
    """
    async with session_factory() as session:
        route = await seed_route(session)
        plaintext_id = await enqueue(
            session, route, PAYLOAD, test_settings, message_id="<clear@ext.com>"
        )

    configure_keys(KEY_A)

    async with session_factory() as session:
        encrypted_id = await enqueue(
            session, route, PAYLOAD, test_settings, message_id="<sealed@ext.com>"
        )
        assert not is_encrypted(json.loads(await raw_cell(session, plaintext_id)))
        assert is_encrypted(json.loads(await raw_cell(session, encrypted_id)))

    before = await auth_client.get(f"/api/v1/delivery-log/{plaintext_id}")
    after = await auth_client.get(f"/api/v1/delivery-log/{encrypted_id}")
    assert before.status_code == after.status_code == 200

    assert after.json()["payload"] == PAYLOAD
    assert after.json()["payload_hash"] == before.json()["payload_hash"]

    # Nothing else about the response shape moved either.
    volatile = {"id", "message_id", "created_at", "updated_at", "next_retry_at"}
    assert {k: v for k, v in after.json().items() if k not in volatile} == {
        k: v for k, v in before.json().items() if k not in volatile
    }


async def test_retry_re_sends_the_stored_payload_unchanged(
    session_factory: async_sessionmaker[AsyncSession],
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test a failed delivery retried later posts the same body, from the same cell.

    The third reader. A retry may happen days after the message arrived, so it
    re-reads the payload from the database rather than holding it; and none of
    ``mark_failed``, ``retry_delivery`` or the re-claim may rewrite the column.
    """
    configure_keys(KEY_A)

    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, PAYLOAD, test_settings)
        ciphertext = await raw_cell(session, delivery_id)

    async with session_factory() as session:
        await mark_failed(session, delivery_id, "HTTP 503", 503, test_settings)
        await retry_delivery(session, delivery_id)
        await session.commit()

    session, claimed = await claim_one(session_factory, delivery_id)
    async with session:
        request = await dispatch(session, claimed, test_settings)
        await session.commit()

    assert json.loads(request.content) == PAYLOAD

    async with session_factory() as session:
        # Byte-identical: the retry read the cell, it did not re-encrypt it.
        assert await raw_cell(session, delivery_id) == ciphertext


async def test_legacy_plaintext_row_is_readable_and_never_converted(
    session_factory: async_sessionmaker[AsyncSession],
    auth_client: AsyncClient,
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test a row written before the key exists survives the whole retention window.

    ``delivery_log`` rows are written once and never rewritten, and the decision
    taken was to let retention age plaintext rows out rather than backfill them
    - so for up to ``delivery_log_retention_days`` a database with a key
    configured holds both shapes at once. Every reader must accept the old one,
    and nothing may quietly "convert" it: a conversion would be an UPDATE per
    row on the largest table in the schema, triggered by reads.
    """
    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, PAYLOAD, test_settings)
        plaintext = await raw_cell(session, delivery_id)
    assert not is_encrypted(json.loads(plaintext))

    configure_keys(KEY_A)

    # Reader one: the ORM.
    assert await load_payload(session_factory, delivery_id) == PAYLOAD

    # Reader two: the detail route.
    response = await auth_client.get(f"/api/v1/delivery-log/{delivery_id}")
    assert response.status_code == 200
    assert response.json()["payload"] == PAYLOAD

    # Reader three: the worker, through failure, retry and delivery - which is
    # every UPDATE the table has.
    session, claimed = await claim_one(session_factory, delivery_id)
    async with session:
        assert claimed.payload == PAYLOAD
        await session.commit()

    async with session_factory() as session:
        await mark_failed(session, delivery_id, "HTTP 500", 500, test_settings)
        await retry_delivery(session, delivery_id)
        await mark_delivered(session, delivery_id)
        await session.commit()

    async with session_factory() as session:
        assert await raw_cell(session, delivery_id) == plaintext


async def test_undecryptable_payload_raises_for_every_reader(
    session_factory: async_sessionmaker[AsyncSession],
    auth_client: AsyncClient,
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test a payload no configured key can read fails loudly, at load time.

    Degrading to ``{}`` would be worse than an outage here: the worker would
    POST an empty body to the customer's endpoint, take the 2xx for it and mark
    the message delivered - destroying the only copy of the message that the
    retention window was holding. The failure has to happen in the claim query,
    before any request is built.
    """
    configure_keys(KEY_A)
    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, PAYLOAD, test_settings)

    configure_keys(KEY_B)

    async with session_factory() as session:
        with pytest.raises(DecryptionError):
            await session.get_one(DeliveryLog, delivery_id)

    # The worker never gets as far as holding a delivery to dispatch.
    async with session_factory() as session:
        with pytest.raises(DecryptionError):
            await get_pending_deliveries(session, batch_size=10)

    # And the detail route surfaces the failure rather than an empty payload.
    with pytest.raises(DecryptionError):
        await auth_client.get(f"/api/v1/delivery-log/{delivery_id}")


async def test_removing_the_key_raises_rather_than_leaking(
    session_factory: async_sessionmaker[AsyncSession],
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test an encrypted payload read with no key at all raises.

    Unsetting the variable is the likeliest operator mistake, and "no key
    configured" is also the shape of a fresh deployment pointed at an existing
    database. The stored value is not plaintext just because the process forgot
    the key, and ``decrypt_json`` must not mistake an envelope for a legacy row.
    """
    configure_keys(KEY_A)
    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, PAYLOAD, test_settings)

    configure_keys()

    async with session_factory() as session:
        with pytest.raises(DecryptionError, match="FASTSMTP_ENCRYPTION_KEYS"):
            await session.get_one(DeliveryLog, delivery_id)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "subject": "Grüße aus München",
            "body_text": "Träume sind Schäume - 値-☃",
            "recipient": "böse@example.com",
        },
    ],
    ids=["empty", "unicode"],
)
async def test_edge_case_payloads_round_trip(
    payload: dict,
    session_factory: async_sessionmaker[AsyncSession],
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test the awkward payloads survive encryption and keep their hash.

    ``{}`` is falsy, so a truthiness test anywhere on the write path would store
    it in clear; and it must come back as ``{}`` rather than None. Non-ASCII
    content goes through serialization, encryption, base64 and a JSON column,
    which is three encodings deep, and a mangled one shows up here.
    """
    configure_keys(KEY_A)

    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, payload, test_settings)
        stored = json.loads(await raw_cell(session, delivery_id))

    assert is_encrypted(stored)

    loaded = await load_payload(session_factory, delivery_id)
    assert loaded == payload
    assert loaded is not None

    async with session_factory() as session:
        delivery = await session.get_one(DeliveryLog, delivery_id)
        assert delivery.payload_hash == compute_payload_hash(payload)


async def test_multi_megabyte_payload_round_trips(
    session_factory: async_sessionmaker[AsyncSession],
    test_settings: Settings,
    configure_keys: Callable[..., None],
) -> None:
    """Test a payload carrying an inline attachment survives at size.

    ``webhook_max_inline_payload_size`` allows 50MB by default, so a payload
    here is an attachment rather than a few fields, and the envelope stores
    roughly 1.33x the plaintext. A few megabytes is enough to catch a size or
    encoding limit without making the suite crawl; the 50MB ceiling is
    deliberately not exercised.
    """
    configure_keys(KEY_A)
    attachment = base64.b64encode(b"\xa5\x5a" * (2 * 1024 * 1024)).decode()
    payload = {
        "subject": "Scan attached",
        "attachments": [{"filename": "scan.pdf", "content": attachment}],
    }

    async with session_factory() as session:
        route = await seed_route(session)
        delivery_id = await enqueue(session, route, payload, test_settings)
        raw = await raw_cell(session, delivery_id)

    stored = json.loads(raw)
    assert is_encrypted(stored)
    # The envelope really carries the whole thing, not a truncation of it.
    assert len(stored["ciphertext"]) > len(attachment)
    assert attachment not in raw

    assert await load_payload(session_factory, delivery_id) == payload


def test_ddl_is_unchanged() -> None:
    """Test the stored type is still JSONB on PostgreSQL and JSON on SQLite.

    This is the claim that let the column adopt encryption with no migration.
    A change to the mapping fails here rather than as schema drift someone
    discovers from ``compare_metadata`` or a production deploy.
    """
    assert column_ddl(postgresql.dialect()) == "payload JSONB NOT NULL"
    assert column_ddl(sqlite.dialect()) == "payload JSON NOT NULL"
