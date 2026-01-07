"""FastAPI authentication dependencies."""

import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.auth.keys import (
    is_key_expired,
    verify_api_key,
    verify_api_key_salted,
)
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import APIKey, Domain, DomainMember, User
from fastsmtp.db.session import get_session

# Domain role hierarchy
ROLE_HIERARCHY = {"owner": 3, "admin": 2, "member": 1}

# Scope definitions
SCOPES = {
    "domains:read",
    "domains:write",
    "domains:delete",
    "members:read",
    "members:write",
    "recipients:read",
    "recipients:write",
    "rules:read",
    "rules:write",
    "logs:read",
    "users:read",
    "users:write",
    "admin",
}


@dataclass
class AuthContext:
    """Authentication context for the current request."""

    user: User
    api_key: APIKey | None
    is_root: bool
    scopes: set[str]

    def has_scope(self, scope: str) -> bool:
        """Check if the context has a specific scope."""
        if self.is_root or "admin" in self.scopes:
            return True
        return scope in self.scopes

    def require_scope(self, scope: str) -> None:
        """Require a specific scope, raising HTTPException if not present."""
        if not self.has_scope(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required scope: {scope}",
            )

    def is_superuser(self) -> bool:
        """Check if the user is a superuser."""
        return self.is_root or self.user.is_superuser

    def require_superuser(self) -> None:
        """Require superuser access, raising HTTPException if not."""
        if not self.is_superuser():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Superuser access required",
            )

    async def get_domain_role(
        self,
        domain_id: uuid.UUID,
        session: AsyncSession,
    ) -> str | None:
        """Get the user's role in a domain.

        Args:
            domain_id: Domain ID to check
            session: Database session

        Returns:
            Role name ('owner', 'admin', 'member') or None if not a member
        """
        if self.is_root:
            return "owner"  # Root has owner access to all domains

        stmt = select(DomainMember).where(
            DomainMember.domain_id == domain_id,
            DomainMember.user_id == self.user.id,
        )
        result = await session.execute(stmt)
        member = result.scalar_one_or_none()
        return member.role if member else None

    async def require_domain_owner(
        self,
        domain_id: uuid.UUID,
        session: AsyncSession,
    ) -> None:
        """Require owner role in a domain.

        Args:
            domain_id: Domain ID to check
            session: Database session

        Raises:
            HTTPException: If user is not an owner of the domain
        """
        if self.is_superuser():
            return

        role = await self.get_domain_role(domain_id, session)
        if role != "owner":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only owners can perform this action",
            )


async def get_auth_context(
    x_api_key: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_session),
    settings: Settings = Depends(get_settings),
) -> AuthContext:
    """Get the authentication context for the current request.

    Validates the API key and returns user information with their scopes.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Check if this is the root API key (timing-safe comparison)
    if secrets.compare_digest(x_api_key, settings.root_api_key.get_secret_value()):
        # Create a virtual root user context
        root_user = User(
            id=uuid.UUID("00000000-0000-0000-0000-000000000000"),
            username="root",
            email=None,
            is_active=True,
            is_superuser=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        return AuthContext(
            user=root_user,
            api_key=None,
            is_root=True,
            scopes=SCOPES,
        )

    # Look up the API key in the database by prefix
    # We use prefix lookup because salted keys can't be looked up by hash directly
    key_prefix = x_api_key[:12] if len(x_api_key) >= 12 else x_api_key
    stmt = (
        select(APIKey)
        .options(selectinload(APIKey.user).selectinload(User.domain_memberships))
        .where(APIKey.key_prefix == key_prefix)
    )
    result = await session.execute(stmt)
    api_key = result.scalar_one_or_none()

    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Verify the key hash (supports both salted and legacy unsalted keys)
    if api_key.is_salted and api_key.key_salt is not None:
        # New salted key verification
        if not verify_api_key_salted(x_api_key, api_key.key_hash, api_key.key_salt):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )
    else:
        # Legacy unsalted key verification
        if not verify_api_key(x_api_key, api_key.key_hash, settings.api_key_hash_algorithm):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid API key",
                headers={"WWW-Authenticate": "ApiKey"},
            )

    if not api_key.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key is inactive",
        )

    if is_key_expired(api_key.expires_at):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has expired",
        )

    if not api_key.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
        )

    # Update last_used_at
    api_key.last_used_at = datetime.now(UTC)

    return AuthContext(
        user=api_key.user,
        api_key=api_key,
        is_root=False,
        scopes=set(api_key.scopes) if api_key.scopes else set(),
    )


# Type alias for dependency injection
Auth = Annotated[AuthContext, Depends(get_auth_context)]


async def get_domain_with_access(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
    required_role: str = "member",
) -> Domain:
    """Get a domain and verify the user has access to it.

    Args:
        domain_id: The domain ID to fetch
        auth: Authentication context
        session: Database session
        required_role: Minimum role required (member, admin, or owner)

    Returns:
        The domain if the user has access

    Raises:
        HTTPException: If domain not found or access denied
    """
    stmt = (
        select(Domain)
        .options(selectinload(Domain.members))
        .where(Domain.id == domain_id)
    )
    result = await session.execute(stmt)
    domain = result.scalar_one_or_none()

    if not domain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    # Superusers have access to all domains
    if auth.is_superuser():
        return domain

    # Check if user is a member of this domain
    membership = next(
        (m for m in domain.members if m.user_id == auth.user.id),
        None,
    )

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied to this domain",
        )

    # Check role hierarchy
    user_role_level = ROLE_HIERARCHY.get(membership.role, 0)
    required_role_level = ROLE_HIERARCHY.get(required_role, 0)

    if user_role_level < required_role_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires {required_role} role or higher",
        )

    return domain


def require_domain_role(required_role: str = "member"):
    """Factory for creating domain access dependencies with specific role requirements."""

    async def dependency(
        domain_id: uuid.UUID,
        auth: Auth,
        session: AsyncSession = Depends(get_session),
    ) -> Domain:
        return await get_domain_with_access(domain_id, auth, session, required_role)

    return dependency


# Pre-configured dependencies for common access patterns
RequireDomainMember = Depends(require_domain_role("member"))
RequireDomainAdmin = Depends(require_domain_role("admin"))
RequireDomainOwner = Depends(require_domain_role("owner"))
