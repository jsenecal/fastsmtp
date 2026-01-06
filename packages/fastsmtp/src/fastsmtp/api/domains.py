"""Domain and member management API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.auth import Auth, get_domain_with_access
from fastsmtp.db.models import Domain, DomainMember, User
from fastsmtp.db.session import get_session
from fastsmtp.schemas import (
    DomainCreate,
    DomainResponse,
    DomainUpdate,
    MemberCreate,
    MemberResponse,
    MemberUpdate,
    MessageResponse,
)

router = APIRouter(prefix="/domains", tags=["domains"])


@router.get("", response_model=list[DomainResponse])
async def list_domains(
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> list[DomainResponse]:
    """List domains accessible to the current user.

    Superusers see all domains; regular users see only their domains.
    """
    if auth.is_superuser():
        stmt = select(Domain).order_by(Domain.domain_name)
    else:
        stmt = (
            select(Domain)
            .join(DomainMember)
            .where(DomainMember.user_id == auth.user.id)
            .order_by(Domain.domain_name)
        )

    result = await session.execute(stmt)
    domains = result.scalars().all()
    return [DomainResponse.model_validate(d) for d in domains]


@router.post("", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    data: DomainCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> DomainResponse:
    """Create a new domain (superuser only)."""
    auth.require_superuser()

    # Check for duplicate domain
    stmt = select(Domain).where(Domain.domain_name == data.domain_name)
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Domain already exists",
        )

    domain = Domain(
        domain_name=data.domain_name,
        verify_dkim=data.verify_dkim,
        verify_spf=data.verify_spf,
        reject_dkim_fail=data.reject_dkim_fail,
        reject_spf_fail=data.reject_spf_fail,
    )
    session.add(domain)
    await session.flush()
    await session.refresh(domain)

    return DomainResponse.model_validate(domain)


@router.get("/{domain_id}", response_model=DomainResponse)
async def get_domain(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> DomainResponse:
    """Get a domain by ID."""
    domain = await get_domain_with_access(domain_id, auth, session, required_role="member")
    return DomainResponse.model_validate(domain)


@router.put("/{domain_id}", response_model=DomainResponse)
async def update_domain(
    domain_id: uuid.UUID,
    data: DomainUpdate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> DomainResponse:
    """Update a domain (admin or higher)."""
    domain = await get_domain_with_access(domain_id, auth, session, required_role="admin")

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(domain, field, value)

    await session.flush()
    await session.refresh(domain)

    return DomainResponse.model_validate(domain)


@router.delete("/{domain_id}", response_model=MessageResponse)
async def delete_domain(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Delete a domain (owner or superuser only)."""
    domain = await get_domain_with_access(domain_id, auth, session, required_role="owner")

    await session.delete(domain)
    return MessageResponse(message=f"Domain {domain.domain_name} deleted")


# Member endpoints


@router.get("/{domain_id}/members", response_model=list[MemberResponse])
async def list_members(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> list[MemberResponse]:
    """List members of a domain."""
    await get_domain_with_access(domain_id, auth, session, required_role="member")

    stmt = (
        select(DomainMember)
        .options(selectinload(DomainMember.user))
        .where(DomainMember.domain_id == domain_id)
        .order_by(DomainMember.role)
    )
    result = await session.execute(stmt)
    members = result.scalars().all()

    responses = []
    for m in members:
        response = MemberResponse.model_validate(m)
        response.username = m.user.username if m.user else None
        responses.append(response)

    return responses


@router.post(
    "/{domain_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED
)
async def add_member(
    domain_id: uuid.UUID,
    data: MemberCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MemberResponse:
    """Add a member to a domain (admin or higher)."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")

    # Check that the user exists
    user_stmt = select(User).where(User.id == data.user_id)
    user_result = await session.execute(user_stmt)
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check for existing membership
    existing_stmt = select(DomainMember).where(
        DomainMember.domain_id == domain_id,
        DomainMember.user_id == data.user_id,
    )
    existing_result = await session.execute(existing_stmt)
    if existing_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User is already a member of this domain",
        )

    # Only owners can add other owners
    if data.role == "owner" and not auth.is_superuser():
        # Check if current user is an owner
        member_stmt = select(DomainMember).where(
            DomainMember.domain_id == domain_id,
            DomainMember.user_id == auth.user.id,
        )
        member_result = await session.execute(member_stmt)
        current_member = member_result.scalar_one_or_none()
        if not current_member or current_member.role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners can add other owners",
            )

    member = DomainMember(
        domain_id=domain_id,
        user_id=data.user_id,
        role=data.role,
    )
    session.add(member)
    await session.flush()
    await session.refresh(member)

    response = MemberResponse.model_validate(member)
    response.username = user.username
    return response


@router.put("/{domain_id}/members/{user_id}", response_model=MemberResponse)
async def update_member(
    domain_id: uuid.UUID,
    user_id: uuid.UUID,
    data: MemberUpdate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MemberResponse:
    """Update a member's role (admin or higher)."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")

    stmt = (
        select(DomainMember)
        .options(selectinload(DomainMember.user))
        .where(
            DomainMember.domain_id == domain_id,
            DomainMember.user_id == user_id,
        )
    )
    result = await session.execute(stmt)
    member = result.scalar_one_or_none()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    # Only owners can promote/demote to/from owner
    if (member.role == "owner" or data.role == "owner") and not auth.is_superuser():
        member_stmt = select(DomainMember).where(
            DomainMember.domain_id == domain_id,
            DomainMember.user_id == auth.user.id,
        )
        member_result = await session.execute(member_stmt)
        current_member = member_result.scalar_one_or_none()
        if not current_member or current_member.role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners can change owner roles",
            )

    member.role = data.role
    await session.flush()
    await session.refresh(member)

    response = MemberResponse.model_validate(member)
    response.username = member.user.username if member.user else None
    return response


@router.delete("/{domain_id}/members/{user_id}", response_model=MessageResponse)
async def remove_member(
    domain_id: uuid.UUID,
    user_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Remove a member from a domain (admin or higher)."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")

    stmt = (
        select(DomainMember)
        .options(selectinload(DomainMember.user))
        .where(
            DomainMember.domain_id == domain_id,
            DomainMember.user_id == user_id,
        )
    )
    result = await session.execute(stmt)
    member = result.scalar_one_or_none()

    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )

    # Only owners can remove other owners
    if member.role == "owner" and not auth.is_superuser():
        member_stmt = select(DomainMember).where(
            DomainMember.domain_id == domain_id,
            DomainMember.user_id == auth.user.id,
        )
        member_result = await session.execute(member_stmt)
        current_member = member_result.scalar_one_or_none()
        if not current_member or current_member.role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners can remove other owners",
            )

    # Don't allow removing yourself
    if not auth.is_root and user_id == auth.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from a domain",
        )

    username = member.user.username if member.user else str(user_id)
    await session.delete(member)
    return MessageResponse(message=f"Member {username} removed from domain")
