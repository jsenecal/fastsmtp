"""Authentication API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import ColumnElement, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.api.validation import IncludeDeleted
from fastsmtp.auth import Auth, generate_api_key
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import APIKey, Domain, DomainMember
from fastsmtp.db.session import get_session
from fastsmtp.db.soft_delete import soft_delete_api_key
from fastsmtp.schemas import (
    APIKeyCreate,
    APIKeyCreateResponse,
    APIKeyResponse,
    MessageResponse,
    UserResponse,
    WhoamiResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


async def _own_live_key(
    session: AsyncSession, auth: Auth, key_id: uuid.UUID, *criteria: ColumnElement[bool]
) -> APIKey:
    """Load one of the caller's keys that is not tombstoned, or 404.

    A tombstone answers the same 404 as an id that never existed.
    """
    stmt = select(APIKey).where(
        APIKey.id == key_id,
        APIKey.user_id == auth.user.id,
        APIKey.live(),
        *criteria,
    )
    result = await session.execute(stmt)
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )
    return api_key


@router.get("/me", response_model=WhoamiResponse)
async def whoami(
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> WhoamiResponse:
    """Get current user information."""
    # Get domain names for the user; memberships in tombstoned domains are
    # hidden until the domain is restored.
    domains: list[str] = []
    if not auth.is_root:
        stmt = (
            select(Domain.domain_name)
            .join(Domain.members)
            .where(DomainMember.user_id == auth.user.id, Domain.live())
        )
        result = await session.execute(stmt)
        domains = list(result.scalars().all())

    return WhoamiResponse(
        user=UserResponse.model_validate(auth.user),
        domains=domains,
        is_root=auth.is_root,
    )


@router.get("/keys", response_model=list[APIKeyResponse])
async def list_keys(
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    include_deleted: IncludeDeleted = False,
) -> list[APIKeyResponse]:
    """List the current user's API keys.

    By default only keys that can still authenticate. ``include_deleted``
    also lists tombstoned keys and keys retired before soft delete existed
    (``is_active`` false, no tombstone); the caller can only ever see their
    own keys, so no further role gate applies.
    """
    if auth.is_root:
        return []

    stmt = select(APIKey).where(APIKey.user_id == auth.user.id)
    if not include_deleted:
        # is_active stays alongside live(): keys retired by a pre-0.5 server
        # carry is_active=False with deleted_at NULL and must stay hidden.
        stmt = stmt.where(APIKey.is_active == True, APIKey.live())  # noqa: E712
    result = await session.execute(stmt)
    keys = result.scalars().all()
    return [APIKeyResponse.model_validate(k) for k in keys]


@router.post("/keys", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_key(
    data: APIKeyCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> APIKeyCreateResponse:
    """Create a new API key for the current user."""
    if auth.is_root:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Root user cannot create API keys. Create a user first.",
        )

    full_key, key_prefix, key_hash, key_salt = generate_api_key()

    api_key = APIKey(
        user_id=auth.user.id,
        key_hash=key_hash,
        key_salt=key_salt,
        key_prefix=key_prefix,
        name=data.name,
        scopes=data.scopes,
        expires_at=data.expires_at,
    )
    session.add(api_key)
    await session.flush()
    await session.refresh(api_key)

    # Build response with key included
    return APIKeyCreateResponse(
        id=api_key.id,
        name=api_key.name,
        scopes=api_key.scopes or [],
        key_prefix=api_key.key_prefix,
        expires_at=api_key.expires_at,
        last_used_at=api_key.last_used_at,
        is_active=api_key.is_active,
        created_at=api_key.created_at,
        key=full_key,
    )


@router.delete("/keys/{key_id}", response_model=MessageResponse)
async def delete_key(
    key_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Delete an API key.

    The key is tombstoned and deactivated; there is no restore for keys, so a
    second delete of the same id answers 404 like any other unknown key.
    """
    if auth.is_root:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Root user has no API keys to delete",
        )

    api_key = await _own_live_key(session, auth, key_id)

    # Don't allow deleting the current key
    if auth.api_key and api_key.id == auth.api_key.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the currently active API key",
        )

    await soft_delete_api_key(session, api_key)
    return MessageResponse(message="API key deleted")


@router.post("/keys/{key_id}/rotate", response_model=APIKeyCreateResponse)
async def rotate_key(
    key_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> APIKeyCreateResponse:
    """Rotate an API key (retire the old one, create a new one with the same settings)."""
    if auth.is_root:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Root user has no API keys to rotate",
        )

    old_key = await _own_live_key(
        session,
        auth,
        key_id,
        APIKey.is_active == True,  # noqa: E712
    )

    await soft_delete_api_key(session, old_key)

    # Create new key with same settings
    full_key, key_prefix, key_hash, key_salt = generate_api_key()
    new_key = APIKey(
        user_id=auth.user.id,
        key_hash=key_hash,
        key_salt=key_salt,
        key_prefix=key_prefix,
        name=f"{old_key.name} (rotated)",
        scopes=old_key.scopes,
        expires_at=old_key.expires_at,
    )
    session.add(new_key)
    await session.flush()
    await session.refresh(new_key)

    # Build response with key included
    return APIKeyCreateResponse(
        id=new_key.id,
        name=new_key.name,
        scopes=new_key.scopes or [],
        key_prefix=new_key.key_prefix,
        expires_at=new_key.expires_at,
        last_used_at=new_key.last_used_at,
        is_active=new_key.is_active,
        created_at=new_key.created_at,
        key=full_key,
    )
