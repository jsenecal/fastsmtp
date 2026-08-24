"""Recipient management API endpoints.

Deletes are soft: ``DELETE`` tombstones the row and cancels its queued
deliveries, ``POST .../restore`` clears the tombstone, and ``DELETE ...?purge=true``
runs the old hard delete on a row that is already tombstoned. Reads hide
tombstones unless ``include_deleted`` is passed, which raises the required
domain role to admin up front so the flag is never an existence oracle.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import ColumnElement, and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.api.validation import (
    IncludeDeleted,
    Purge,
    flush_or_http_conflict,
    require_tombstoned,
)
from fastsmtp.auth import Auth, get_domain_with_access
from fastsmtp.db import soft_delete
from fastsmtp.db.models import Recipient
from fastsmtp.db.session import get_session
from fastsmtp.schemas.common import MessageResponse
from fastsmtp.schemas.recipient import RecipientCreate, RecipientResponse, RecipientUpdate

router = APIRouter(tags=["recipients"])


def _conflicting_local_part(local_part: str | None) -> ColumnElement[bool]:
    """Filter for live rows that conflict with creating ``local_part``.

    Mirrors what the database enforces: both unique indexes
    (``uq_recipient_local_part`` and ``ix_recipients_domain_catchall``) only
    cover live rows, so a soft-deleted recipient never blocks recreating the
    same local part or catch-all.
    """
    matches = Recipient.local_part == local_part if local_part else Recipient.local_part.is_(None)
    return and_(matches, Recipient.live())


async def _local_part_taken(
    session: AsyncSession,
    domain_id: uuid.UUID,
    local_part: str | None,
    *,
    exclude_id: uuid.UUID | None = None,
) -> bool:
    """Duplicate pre-check shared by create, update and restore.

    The check is check-then-flush; the partial unique indexes are the
    backstop, translated by ``flush_or_http_conflict``.
    """
    stmt = select(Recipient.id).where(
        Recipient.domain_id == domain_id, _conflicting_local_part(local_part)
    )
    if exclude_id is not None:
        stmt = stmt.where(Recipient.id != exclude_id)
    return (await session.execute(stmt)).first() is not None


def _duplicate_conflict(local_part: str | None) -> HTTPException:
    pattern = local_part or "catch-all (*)"
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=f"Recipient '{pattern}' already exists for this domain",
    )


async def _get_recipient_or_404(
    session: AsyncSession,
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID,
    *,
    include_deleted: bool = False,
) -> Recipient:
    """Load a recipient of ``domain_id``, 404 when missing - or tombstoned, unless asked for."""
    stmt = select(Recipient).where(
        Recipient.id == recipient_id,
        Recipient.domain_id == domain_id,
        soft_delete.visible(Recipient, include_deleted),
    )
    recipient = (await session.execute(stmt)).scalar_one_or_none()
    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        )
    return recipient


def _read_role(include_deleted: bool) -> str:
    """Members read live rows; tombstones need the role that may delete them."""
    return "admin" if include_deleted else "member"


@router.get("/domains/{domain_id}/recipients", response_model=list[RecipientResponse])
async def list_recipients(
    domain_id: uuid.UUID,
    auth: Auth,
    include_deleted: IncludeDeleted = False,
    session: AsyncSession = Depends(get_session),
) -> list[RecipientResponse]:
    """List all recipients for a domain.

    With ``include_deleted`` the domain is resolved with the same flag, so an
    owner or superuser can audit a tombstoned domain's recipients before
    restoring it.
    """
    await get_domain_with_access(
        domain_id,
        auth,
        session,
        required_role=_read_role(include_deleted),
        include_deleted=include_deleted,
    )
    auth.require_scope("recipients:read")

    stmt = (
        select(Recipient)
        .where(Recipient.domain_id == domain_id, soft_delete.visible(Recipient, include_deleted))
        .order_by(Recipient.local_part.nulls_last())
    )
    result = await session.execute(stmt)
    recipients = result.scalars().all()
    return [RecipientResponse.model_validate(r) for r in recipients]


@router.post(
    "/domains/{domain_id}/recipients",
    response_model=RecipientResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_recipient(
    domain_id: uuid.UUID,
    data: RecipientCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RecipientResponse:
    """Create a new recipient for a domain."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("recipients:write")

    # Normalize local_part: "*" or empty string means catch-all (NULL)
    local_part = data.local_part
    if local_part in ("*", ""):
        local_part = None

    if await _local_part_taken(session, domain_id, local_part):
        raise _duplicate_conflict(local_part)

    recipient = Recipient(
        domain_id=domain_id,
        local_part=local_part,
        webhook_url=str(data.webhook_url),
        webhook_headers=data.webhook_headers,
    )
    session.add(recipient)
    await flush_or_http_conflict(session, _duplicate_conflict(local_part))
    await session.refresh(recipient)

    return RecipientResponse.model_validate(recipient)


@router.get("/domains/{domain_id}/recipients/{recipient_id}", response_model=RecipientResponse)
async def get_recipient(
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID,
    auth: Auth,
    include_deleted: IncludeDeleted = False,
    session: AsyncSession = Depends(get_session),
) -> RecipientResponse:
    """Get a recipient by ID."""
    await get_domain_with_access(
        domain_id,
        auth,
        session,
        required_role=_read_role(include_deleted),
        include_deleted=include_deleted,
    )
    auth.require_scope("recipients:read")

    recipient = await _get_recipient_or_404(
        session, domain_id, recipient_id, include_deleted=include_deleted
    )
    return RecipientResponse.model_validate(recipient)


@router.put("/domains/{domain_id}/recipients/{recipient_id}", response_model=RecipientResponse)
async def update_recipient(
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID,
    data: RecipientUpdate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RecipientResponse:
    """Update a recipient."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("recipients:write")

    recipient = await _get_recipient_or_404(session, domain_id, recipient_id)

    update_data = data.model_dump(exclude_unset=True)

    # Handle local_part normalization
    if "local_part" in update_data:
        local_part = update_data["local_part"]
        if local_part in ("*", ""):
            update_data["local_part"] = None

        # Check for duplicate if changing local_part
        new_local_part = update_data["local_part"]
        if new_local_part != recipient.local_part and await _local_part_taken(
            session, domain_id, new_local_part, exclude_id=recipient_id
        ):
            raise _duplicate_conflict(new_local_part)

    # Handle webhook_url conversion
    if "webhook_url" in update_data and update_data["webhook_url"]:
        update_data["webhook_url"] = str(update_data["webhook_url"])

    for field, value in update_data.items():
        setattr(recipient, field, value)

    await flush_or_http_conflict(session, _duplicate_conflict(recipient.local_part))
    await session.refresh(recipient)

    return RecipientResponse.model_validate(recipient)


@router.delete("/domains/{domain_id}/recipients/{recipient_id}")
async def delete_recipient(
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID,
    auth: Auth,
    purge: Purge = False,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Soft-delete a recipient, or with ``purge`` hard-delete an already deleted one.

    A soft delete cancels the recipient's pending and failed deliveries in
    the same transaction, so nothing goes out to a deleted endpoint. Purge is
    superuser-only and only reachable on a tombstone, so a wrong id is never
    a one-shot loss; the domain may itself be tombstoned by then.
    """
    if purge:
        auth.require_superuser()
    await get_domain_with_access(
        domain_id, auth, session, required_role="admin", include_deleted=purge
    )
    auth.require_scope("recipients:write")

    recipient = await _get_recipient_or_404(session, domain_id, recipient_id, include_deleted=purge)
    pattern = recipient.local_part or "*"

    if purge:
        require_tombstoned(recipient, "Recipient must be deleted before it can be purged")
        await soft_delete.purge_recipient(session, recipient)
        return MessageResponse(message=f"Recipient '{pattern}' purged")

    await soft_delete.soft_delete_recipient(session, recipient)
    return MessageResponse(message=f"Recipient '{pattern}' deleted")


@router.post(
    "/domains/{domain_id}/recipients/{recipient_id}/restore", response_model=RecipientResponse
)
async def restore_recipient(
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RecipientResponse:
    """Restore a soft-deleted recipient.

    The domain must be live (restore it first otherwise). Clears the
    tombstone and nothing else: deliveries cancelled at delete time stay
    cancelled until retried explicitly. 409 when the recipient is live or its
    local part has been re-taken.
    """
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("recipients:write")

    recipient = await _get_recipient_or_404(session, domain_id, recipient_id, include_deleted=True)
    require_tombstoned(recipient, "Recipient is not deleted")

    if await _local_part_taken(session, domain_id, recipient.local_part, exclude_id=recipient.id):
        raise _duplicate_conflict(recipient.local_part)

    await soft_delete.restore_recipient(session, recipient)
    await flush_or_http_conflict(session, _duplicate_conflict(recipient.local_part))
    await session.refresh(recipient)

    return RecipientResponse.model_validate(recipient)
