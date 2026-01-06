"""Recipient management API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.auth import Auth, get_domain_with_access
from fastsmtp.db.models import Recipient
from fastsmtp.db.session import get_session
from fastsmtp.schemas.recipient import RecipientCreate, RecipientResponse, RecipientUpdate

router = APIRouter(tags=["recipients"])


@router.get("/domains/{domain_id}/recipients", response_model=list[RecipientResponse])
async def list_recipients(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> list[RecipientResponse]:
    """List all recipients for a domain."""
    await get_domain_with_access(domain_id, auth, session, required_role="member")
    auth.require_scope("recipients:read")

    stmt = (
        select(Recipient)
        .where(Recipient.domain_id == domain_id)
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

    # Check for duplicate
    stmt = select(Recipient).where(
        Recipient.domain_id == domain_id,
        Recipient.local_part == local_part if local_part else Recipient.local_part.is_(None),
    )
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        pattern = local_part or "catch-all (*)"
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Recipient '{pattern}' already exists for this domain",
        )

    recipient = Recipient(
        domain_id=domain_id,
        local_part=local_part,
        webhook_url=str(data.webhook_url),
        webhook_headers=data.webhook_headers,
    )
    session.add(recipient)
    await session.flush()
    await session.refresh(recipient)

    return RecipientResponse.model_validate(recipient)


@router.get("/domains/{domain_id}/recipients/{recipient_id}", response_model=RecipientResponse)
async def get_recipient(
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RecipientResponse:
    """Get a recipient by ID."""
    await get_domain_with_access(domain_id, auth, session, required_role="member")
    auth.require_scope("recipients:read")

    stmt = select(Recipient).where(
        Recipient.id == recipient_id,
        Recipient.domain_id == domain_id,
    )
    result = await session.execute(stmt)
    recipient = result.scalar_one_or_none()

    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
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

    stmt = select(Recipient).where(
        Recipient.id == recipient_id,
        Recipient.domain_id == domain_id,
    )
    result = await session.execute(stmt)
    recipient = result.scalar_one_or_none()

    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        )

    update_data = data.model_dump(exclude_unset=True)

    # Handle local_part normalization
    if "local_part" in update_data:
        local_part = update_data["local_part"]
        if local_part in ("*", ""):
            update_data["local_part"] = None

        # Check for duplicate if changing local_part
        new_local_part = update_data["local_part"]
        if new_local_part != recipient.local_part:
            check_stmt = select(Recipient).where(
                Recipient.domain_id == domain_id,
                Recipient.id != recipient_id,
                Recipient.local_part == new_local_part
                if new_local_part
                else Recipient.local_part.is_(None),
            )
            check_result = await session.execute(check_stmt)
            if check_result.scalar_one_or_none():
                pattern = new_local_part or "catch-all (*)"
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Recipient '{pattern}' already exists for this domain",
                )

    # Handle webhook_url conversion
    if "webhook_url" in update_data and update_data["webhook_url"]:
        update_data["webhook_url"] = str(update_data["webhook_url"])

    for field, value in update_data.items():
        setattr(recipient, field, value)

    await session.flush()
    await session.refresh(recipient)

    return RecipientResponse.model_validate(recipient)


@router.delete("/domains/{domain_id}/recipients/{recipient_id}")
async def delete_recipient(
    domain_id: uuid.UUID,
    recipient_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Delete a recipient."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("recipients:write")

    stmt = select(Recipient).where(
        Recipient.id == recipient_id,
        Recipient.domain_id == domain_id,
    )
    result = await session.execute(stmt)
    recipient = result.scalar_one_or_none()

    if not recipient:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        )

    pattern = recipient.local_part or "*"
    await session.delete(recipient)
    return {"message": f"Recipient '{pattern}' deleted"}
