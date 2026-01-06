"""Authentication API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.auth import Auth, generate_api_key
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import APIKey, DomainMember
from fastsmtp.db.session import get_session
from fastsmtp.schemas import (
    APIKeyCreate,
    APIKeyCreateResponse,
    APIKeyResponse,
    MessageResponse,
    UserResponse,
    WhoamiResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me", response_model=WhoamiResponse)
async def whoami(
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> WhoamiResponse:
    """Get current user information."""
    # Get domain names for the user
    domains: list[str] = []
    if not auth.is_root:
        stmt = (
            select(DomainMember)
            .options(selectinload(DomainMember.domain))
            .where(DomainMember.user_id == auth.user.id)
        )
        result = await session.execute(stmt)
        memberships = result.scalars().all()
        domains = [m.domain.domain_name for m in memberships]

    return WhoamiResponse(
        user=UserResponse.model_validate(auth.user),
        domains=domains,
        is_root=auth.is_root,
    )


@router.get("/keys", response_model=list[APIKeyResponse])
async def list_keys(
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> list[APIKeyResponse]:
    """List all API keys for the current user."""
    if auth.is_root:
        return []

    stmt = select(APIKey).where(
        APIKey.user_id == auth.user.id,
        APIKey.is_active == True,  # noqa: E712
    )
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

    full_key, key_prefix, key_hash = generate_api_key()

    api_key = APIKey(
        user_id=auth.user.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=data.name,
        scopes=data.scopes,
        expires_at=data.expires_at,
    )
    session.add(api_key)
    await session.flush()
    await session.refresh(api_key)

    response = APIKeyCreateResponse.model_validate(api_key)
    response.key = full_key
    return response


@router.delete("/keys/{key_id}", response_model=MessageResponse)
async def delete_key(
    key_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Delete an API key."""
    if auth.is_root:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Root user has no API keys to delete",
        )

    stmt = select(APIKey).where(
        APIKey.id == key_id,
        APIKey.user_id == auth.user.id,
    )
    result = await session.execute(stmt)
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    # Don't allow deleting the current key
    if auth.api_key and api_key.id == auth.api_key.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete the currently active API key",
        )

    api_key.is_active = False
    return MessageResponse(message="API key deleted")


@router.post("/keys/{key_id}/rotate", response_model=APIKeyCreateResponse)
async def rotate_key(
    key_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> APIKeyCreateResponse:
    """Rotate an API key (deactivate old, create new with same settings)."""
    if auth.is_root:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Root user has no API keys to rotate",
        )

    stmt = select(APIKey).where(
        APIKey.id == key_id,
        APIKey.user_id == auth.user.id,
        APIKey.is_active == True,  # noqa: E712
    )
    result = await session.execute(stmt)
    old_key = result.scalar_one_or_none()

    if not old_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key not found",
        )

    # Deactivate old key
    old_key.is_active = False

    # Create new key with same settings
    full_key, key_prefix, key_hash = generate_api_key()
    new_key = APIKey(
        user_id=auth.user.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        name=f"{old_key.name} (rotated)",
        scopes=old_key.scopes,
        expires_at=old_key.expires_at,
    )
    session.add(new_key)
    await session.flush()
    await session.refresh(new_key)

    response = APIKeyCreateResponse.model_validate(new_key)
    response.key = full_key
    return response
