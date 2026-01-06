"""Authentication module."""

from fastsmtp.auth.dependencies import (
    Auth,
    AuthContext,
    RequireDomainAdmin,
    RequireDomainMember,
    RequireDomainOwner,
    get_auth_context,
    get_domain_with_access,
    require_domain_role,
)
from fastsmtp.auth.keys import generate_api_key, hash_api_key, is_key_expired, verify_api_key

__all__ = [
    "Auth",
    "AuthContext",
    "RequireDomainAdmin",
    "RequireDomainMember",
    "RequireDomainOwner",
    "generate_api_key",
    "get_auth_context",
    "get_domain_with_access",
    "hash_api_key",
    "is_key_expired",
    "require_domain_role",
    "verify_api_key",
]
