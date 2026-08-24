"""Domain and member management API endpoints.

Deletes are soft: ``DELETE`` tombstones the domain, stamps its live recipients
with the same timestamp and cancels their queued deliveries; ``POST
.../restore`` clears the tombstone (and the recipients stamped with it); ``DELETE
...?purge=true`` runs the old hard delete on a row that is already tombstoned.
Reads hide tombstones unless ``include_deleted`` is passed, which raises the
required role to owner *before* the lookup so the flag is never an existence
oracle. Rulesets, rules and memberships carry no tombstone of their own: they
are unreachable while the domain is tombstoned (every nested route resolves
the domain first) and return unchanged on restore.

Memberships of a tombstoned *user* are hidden the same way, through the user
filter on the member routes, until that user is restored.
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import ColumnElement, Select, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.api.validation import (
    IncludeDeleted,
    Purge,
    flush_or_http_conflict,
    live_value_taken,
    require_s3_for_preservation,
    require_tombstoned,
)
from fastsmtp.auth import Auth, get_domain_with_access
from fastsmtp.config import Settings, get_settings
from fastsmtp.db import soft_delete
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


def _duplicate_domain_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Domain already exists",
    )


def _membership(domain_id: uuid.UUID, user_id: uuid.UUID) -> ColumnElement[bool]:
    """Filter for one user's membership in one domain.

    This pair is what ``uq_domain_member`` keys on, so the same filter serves
    both as the row lookup and as the duplicate pre-check before an insert.
    """
    return and_(DomainMember.domain_id == domain_id, DomainMember.user_id == user_id)


def _live_members() -> Select[tuple[DomainMember]]:
    """Memberships whose user is live, with the user loaded.

    A tombstoned user's membership is hidden - not listed, not editable, not
    removable - until the user is restored, so no role can change on a dead
    principal and the edge comes back intact with the account. The join only
    filters; ``selectinload`` (not ``contains_eager``) does the loading because
    it is what ``session.refresh`` re-applies after the update routes flush.
    """
    return (
        select(DomainMember)
        .join(DomainMember.user)
        .options(selectinload(DomainMember.user))
        .where(User.live())
    )


def _duplicate_member_conflict() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="User is already a member of this domain",
    )


async def _get_live_member_or_404(
    session: AsyncSession, domain_id: uuid.UUID, user_id: uuid.UUID
) -> DomainMember:
    """Load one membership, 404 when missing - or when its user is tombstoned."""
    stmt = _live_members().where(_membership(domain_id, user_id))
    member = (await session.execute(stmt)).scalar_one_or_none()
    if not member:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Member not found",
        )
    return member


def _member_response(member: DomainMember) -> MemberResponse:
    response = MemberResponse.model_validate(member)
    response.username = member.user.username if member.user else None
    return response


@router.get("", response_model=list[DomainResponse])
async def list_domains(
    auth: Auth,
    include_deleted: IncludeDeleted = False,
    session: AsyncSession = Depends(get_session),
) -> list[DomainResponse]:
    """List domains accessible to the current user.

    Superusers see all domains; regular users see only their domains. With
    ``include_deleted`` a superuser also sees tombstones, and a regular user
    only the tombstoned domains they own - the role that may delete them.
    """
    if auth.is_superuser():
        stmt = select(Domain).where(soft_delete.visible(Domain, include_deleted))
    else:
        stmt = select(Domain).join(DomainMember).where(DomainMember.user_id == auth.user.id)
        if include_deleted:
            stmt = stmt.where(or_(Domain.live(), DomainMember.role == "owner"))
        else:
            stmt = stmt.where(Domain.live())

    result = await session.execute(stmt.order_by(Domain.domain_name))
    domains = result.scalars().all()
    return [DomainResponse.model_validate(d) for d in domains]


@router.post("", response_model=DomainResponse, status_code=status.HTTP_201_CREATED)
async def create_domain(
    data: DomainCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DomainResponse:
    """Create a new domain (superuser only)."""
    auth.require_superuser()

    if data.preserve_raw_message:
        require_s3_for_preservation(settings)

    if await live_value_taken(session, Domain, Domain.domain_name, data.domain_name):
        raise _duplicate_domain_conflict()

    domain = Domain(
        domain_name=data.domain_name,
        verify_dkim=data.verify_dkim,
        verify_spf=data.verify_spf,
        reject_dkim_fail=data.reject_dkim_fail,
        reject_spf_fail=data.reject_spf_fail,
        preserve_raw_message=data.preserve_raw_message,
    )
    session.add(domain)
    await flush_or_http_conflict(session, _duplicate_domain_conflict())
    await session.refresh(domain)

    return DomainResponse.model_validate(domain)


@router.get("/{domain_id}", response_model=DomainResponse)
async def get_domain(
    domain_id: uuid.UUID,
    auth: Auth,
    include_deleted: IncludeDeleted = False,
    session: AsyncSession = Depends(get_session),
) -> DomainResponse:
    """Get a domain by ID. A tombstone is 404 unless ``include_deleted`` (owner)."""
    domain = await get_domain_with_access(
        domain_id,
        auth,
        session,
        required_role="owner" if include_deleted else "member",
        include_deleted=include_deleted,
    )
    return DomainResponse.model_validate(domain)


@router.put("/{domain_id}", response_model=DomainResponse)
async def update_domain(
    domain_id: uuid.UUID,
    data: DomainUpdate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> DomainResponse:
    """Update a domain (admin or higher)."""
    domain = await get_domain_with_access(domain_id, auth, session, required_role="admin")

    update_data = data.model_dump(exclude_unset=True)

    if update_data.get("preserve_raw_message"):
        require_s3_for_preservation(settings)
    for field, value in update_data.items():
        setattr(domain, field, value)

    await session.flush()
    await session.refresh(domain)

    return DomainResponse.model_validate(domain)


@router.delete("/{domain_id}", response_model=MessageResponse)
async def delete_domain(
    domain_id: uuid.UUID,
    auth: Auth,
    purge: Purge = False,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Soft-delete a domain (owner or superuser), or with ``purge`` hard-delete
    an already deleted one (superuser only).

    A soft delete tombstones the domain and its live recipients with one
    timestamp and cancels their queued deliveries; history keeps its links.
    Purge is only reachable on a tombstone so a wrong id is never a one-shot
    loss; it cascades recipients, rulesets, rules and members and leaves the
    delivery log orphaned (``domain_id`` / ``recipient_id`` set NULL).
    """
    if purge:
        auth.require_superuser()
        domain = await get_domain_with_access(
            domain_id, auth, session, required_role="owner", include_deleted=True
        )
        require_tombstoned(domain, "Domain must be deleted before it can be purged")
        await soft_delete.purge_domain(session, domain)
        return MessageResponse(message=f"Domain {domain.domain_name} purged")

    domain = await get_domain_with_access(domain_id, auth, session, required_role="owner")
    await soft_delete.soft_delete_domain(session, domain)
    return MessageResponse(message=f"Domain {domain.domain_name} deleted")


@router.post("/{domain_id}/restore", response_model=DomainResponse)
async def restore_domain(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> DomainResponse:
    """Restore a soft-deleted domain (owner or superuser).

    Clears the domain's tombstone and those of the recipients stamped with it;
    a recipient deleted on its own earlier stays deleted. Cancelled deliveries
    stay cancelled (retry them explicitly). 409 when the domain is live or its
    name has been re-taken.
    """
    domain = await get_domain_with_access(
        domain_id, auth, session, required_role="owner", include_deleted=True
    )
    require_tombstoned(domain, "Domain is not deleted")

    if await live_value_taken(session, Domain, Domain.domain_name, domain.domain_name):
        raise _duplicate_domain_conflict()

    await soft_delete.restore_domain(session, domain)
    await flush_or_http_conflict(session, _duplicate_domain_conflict())
    await session.refresh(domain)

    return DomainResponse.model_validate(domain)


# Member endpoints


@router.get("/{domain_id}/members", response_model=list[MemberResponse])
async def list_members(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> list[MemberResponse]:
    """List members of a domain (tombstoned users omitted)."""
    await get_domain_with_access(domain_id, auth, session, required_role="member")

    stmt = _live_members().where(DomainMember.domain_id == domain_id).order_by(DomainMember.role)
    result = await session.execute(stmt)
    return [_member_response(m) for m in result.scalars().all()]


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

    # Check that the user exists (a tombstoned user is not found)
    user_stmt = select(User).where(User.id == data.user_id, User.live())
    user_result = await session.execute(user_stmt)
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Check for existing membership
    existing_stmt = select(DomainMember).where(_membership(domain_id, data.user_id))
    existing_result = await session.execute(existing_stmt)
    if existing_result.scalar_one_or_none():
        raise _duplicate_member_conflict()

    # Only owners can add other owners
    if data.role == "owner":
        await auth.require_domain_owner(domain_id, session)

    member = DomainMember(
        domain_id=domain_id,
        user_id=data.user_id,
        role=data.role,
    )
    session.add(member)
    await flush_or_http_conflict(session, _duplicate_member_conflict())
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

    member = await _get_live_member_or_404(session, domain_id, user_id)

    # Only owners can promote/demote to/from owner
    if member.role == "owner" or data.role == "owner":
        await auth.require_domain_owner(domain_id, session)

    member.role = data.role
    await session.flush()
    await session.refresh(member)

    return _member_response(member)


@router.delete("/{domain_id}/members/{user_id}", response_model=MessageResponse)
async def remove_member(
    domain_id: uuid.UUID,
    user_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> MessageResponse:
    """Remove a member from a domain (admin or higher). The edge is hard-deleted."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")

    member = await _get_live_member_or_404(session, domain_id, user_id)

    # Only owners can remove other owners
    if member.role == "owner":
        await auth.require_domain_owner(domain_id, session)

    # Don't allow removing yourself
    if not auth.is_root and user_id == auth.user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove yourself from a domain",
        )

    username = member.user.username if member.user else str(user_id)
    await session.delete(member)
    return MessageResponse(message=f"Member {username} removed from domain")
