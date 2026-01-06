"""User management API endpoints (superuser only)."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastsmtp.auth import Auth
from fastsmtp.db.models import User
from fastsmtp.db.session import get_session
from fastsmtp.schemas import MessageResponse, UserCreate, UserResponse, UserUpdate

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserResponse])
async def list_users(
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> list[UserResponse]:
    """List all users (superuser only)."""
    auth.require_superuser()

    stmt = select(User).order_by(User.username)
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

    # Check for duplicate username
    stmt = select(User).where(User.username == data.username)
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists",
        )

    user = User(
        username=data.username,
        email=data.email,
        is_superuser=data.is_superuser,
    )
    session.add(user)
    await session.flush()
    await session.refresh(user)

    return UserResponse.model_validate(user)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> UserResponse:
    """Get a user by ID (superuser only)."""
    auth.require_superuser()

    stmt = select(User).where(User.id == user_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

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

    stmt = select(User).where(User.id == user_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check for duplicate username if changing
    if data.username and data.username != user.username:
        check_stmt = select(User).where(User.username == data.username)
        check_result = await session.execute(check_stmt)
        if check_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )

    # Update fields
    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(user, field, value)

    await session.flush()
    await session.refresh(user)

    return UserResponse.model_validate(user)


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Delete a user (superuser only)."""
    auth.require_superuser()

    stmt = select(User).where(User.id == user_id)
    result = await session.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Don't allow deleting the current user
    if not auth.is_root and user.id == auth.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    await session.delete(user)
    return MessageResponse(message=f"User {user.username} deleted")
