"""User management API endpoints (superuser only).

Deletes are soft: ``DELETE`` tombstones the row (and revokes its API keys),
``POST …/restore`` clears the tombstone, and ``DELETE …?purge=true`` runs the
old hard delete on a row that is already tombstoned. Reads hide tombstones
unless ``include_deleted`` is passed; every route requires superuser up front,
so neither flag can act as an existence oracle below that role.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.api.validation import (
    IncludeDeleted,
    Purge,
    flush_or_http_conflict,
    require_tombstoned,
)
from fastsmtp.auth import Auth
from fastsmtp.db import soft_delete
from fastsmtp.db.models import User
from fastsmtp.db.session import get_session
from fastsmtp.schemas import MessageResponse, UserCreate, UserResponse, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


async def _live_username_taken(session: AsyncSession, username: str) -> bool:
    """Duplicate pre-check shared by create, update and restore.

    Mirrors what the database enforces: ``ix_users_username`` is partial over
    live rows (migration 008), so a tombstoned user never blocks its name.
    The check is check-then-flush; the index is the backstop, translated by
    ``flush_or_http_conflict``.
    """
    stmt = select(User.id).where(User.username == username, User.live())
    return (await session.execute(stmt)).first() is not None


def _duplicate_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Username already exists",
    )


async def _get_user_or_404(
    session: AsyncSession, user_id: uuid.UUID, *, include_deleted: bool = False
) -> User:
    """Load a user by id, 404 when missing - or tombstoned, unless asked for."""
    stmt = select(User).where(User.id == user_id, soft_delete.visible(User, include_deleted))
    user = (await session.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user


@router.get("", response_model=list[UserResponse])
async def list_users(
    auth: Auth,
    include_deleted: IncludeDeleted = False,
    session: AsyncSession = Depends(get_session),
) -> list[UserResponse]:
    """List all users (superuser only)."""
    auth.require_superuser()

    stmt = select(User).where(soft_delete.visible(User, include_deleted)).order_by(User.username)
    result = await session.execute(stmt)
    users = result.scalars().all()
    return [UserResponse.model_validate(u) for u in users]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    data: UserCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """Create a new user (superuser only)."""
    auth.require_superuser()

    if await _live_username_taken(session, data.username):
        raise _duplicate_conflict()

    user = User(
        username=data.username,
        email=data.email,
        is_superuser=data.is_superuser,
    )
    session.add(user)
    await flush_or_http_conflict(session, _duplicate_conflict())
    await session.refresh(user)

    return UserResponse.model_validate(user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID,
    auth: Auth,
    include_deleted: IncludeDeleted = False,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """Get a user by ID (superuser only)."""
    auth.require_superuser()

    user = await _get_user_or_404(session, user_id, include_deleted=include_deleted)
    return UserResponse.model_validate(user)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    data: UserUpdate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """Update a user (superuser only)."""
    auth.require_superuser()

    user = await _get_user_or_404(session, user_id)

    # Check for duplicate username if changing
    if (
        data.username
        and data.username != user.username
        and await _live_username_taken(session, data.username)
    ):
        raise _duplicate_conflict()

    # Update fields
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    await flush_or_http_conflict(session, _duplicate_conflict())
    await session.refresh(user)

    return UserResponse.model_validate(user)


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: uuid.UUID,
    auth: Auth,
    purge: Purge = False,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Soft-delete a user, or with ``purge`` hard-delete an already deleted one.

    Superuser only. A soft delete revokes the user's API keys for good and
    hides the row until it is restored; memberships are left in place. Purge
    is only reachable on a tombstone so a wrong id is never a one-shot loss.
    """
    auth.require_superuser()

    user = await _get_user_or_404(session, user_id, include_deleted=purge)

    # Don't allow deleting the current user
    if not auth.is_root and user.id == auth.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    if purge:
        require_tombstoned(user, "User must be deleted before it can be purged")
        await soft_delete.purge_user(session, user)
        return MessageResponse(message=f"User {user.username} purged")

    await soft_delete.soft_delete_user(session, user)
    return MessageResponse(message=f"User {user.username} deleted")


@router.post("/{user_id}/restore", response_model=UserResponse)
async def restore_user(
    user_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """Restore a soft-deleted user (superuser only).

    Clears the tombstone and nothing else: API keys revoked at delete time
    stay revoked. 409 when the user is live or its username has been re-taken.
    """
    auth.require_superuser()

    user = await _get_user_or_404(session, user_id, include_deleted=True)
    require_tombstoned(user, "User is not deleted")

    if await _live_username_taken(session, user.username):
        raise _duplicate_conflict()

    await soft_delete.restore_user(session, user)
    await flush_or_http_conflict(session, _duplicate_conflict())
    await session.refresh(user)

    return UserResponse.model_validate(user)
