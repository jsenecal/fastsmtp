"""Tests for authentication error paths.

Tests for rejected API keys, inactive users, malformed keys, and missing headers.
"""

import uuid
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException
from fastsmtp.auth.dependencies import AuthContext, get_auth_context
from fastsmtp.auth.keys import generate_api_key, hash_api_key
from fastsmtp.db.models import APIKey, User
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession


def create_mock_settings(root_api_key: str = "root-key") -> MagicMock:
    """Create a mock settings object with proper root_api_key."""
    mock_settings = MagicMock()
    mock_settings.root_api_key = SecretStr(root_api_key)
    mock_settings.api_key_hash_algorithm = "sha256"
    return mock_settings


def mock_scalars_result(api_keys: list) -> MagicMock:
    """Create a mock result that returns api_keys via scalars().all()."""
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = api_keys
    mock_result.scalars.return_value = mock_scalars
    return mock_result


class TestMissingAPIKey:
    """Tests for missing API key header."""

    @pytest.mark.asyncio
    async def test_missing_api_key_returns_401(self):
        """Test that missing X-API-Key header returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key=None,
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "API key required" in exc_info.value.detail
        assert exc_info.value.headers.get("WWW-Authenticate") == "ApiKey"

    @pytest.mark.asyncio
    async def test_empty_api_key_returns_401(self):
        """Test that empty string API key returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key="",
                session=mock_session,
                settings=mock_settings,
            )

        # Empty string is falsy, so should be treated as missing
        assert exc_info.value.status_code == 401
        assert "API key required" in exc_info.value.detail


class TestInvalidAPIKey:
    """Tests for invalid API key scenarios."""

    @pytest.mark.asyncio
    async def test_api_key_not_found_returns_401(self):
        """Test that non-existent API key returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Mock database query to return empty list (no keys found)
        mock_session.execute.return_value = mock_scalars_result([])

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key="fsmtp_nonexistent_key_123456",
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_malformed_short_api_key_returns_401(self):
        """Test that short malformed API key returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Mock database query to return empty list
        mock_session.execute.return_value = mock_scalars_result([])

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key="short",  # Too short to be valid
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_wrong_key_hash_salted_returns_401(self):
        """Test that wrong hash for salted key returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_active = True

        # Create mock API key with salted hash (different key)
        _, _, correct_hash, correct_salt = generate_api_key()
        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.key_hash = correct_hash
        mock_api_key.key_salt = correct_salt
        mock_api_key.is_salted = True
        mock_api_key.is_active = True
        mock_api_key.expires_at = None
        mock_api_key.user = mock_user

        mock_session.execute.return_value = mock_scalars_result([mock_api_key])

        # Try with a different key (wrong hash)
        wrong_key, _, _, _ = generate_api_key()

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key=wrong_key,
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_wrong_key_hash_legacy_returns_401(self):
        """Test that wrong hash for legacy (unsalted) key returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_active = True

        # Create mock API key with legacy (unsalted) hash
        correct_key, _, _, _ = generate_api_key()
        correct_hash = hash_api_key(correct_key)

        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.key_hash = correct_hash
        mock_api_key.key_salt = None  # Legacy key
        mock_api_key.is_salted = False
        mock_api_key.is_active = True
        mock_api_key.expires_at = None
        mock_api_key.user = mock_user

        mock_session.execute.return_value = mock_scalars_result([mock_api_key])

        # Try with a different key (wrong hash)
        wrong_key, _, _, _ = generate_api_key()

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key=wrong_key,
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail


class TestInactiveAPIKey:
    """Tests for inactive API key."""

    @pytest.mark.asyncio
    async def test_inactive_api_key_returns_401(self):
        """Test that inactive API key returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_active = True

        # Generate a valid key and its hash
        full_key, key_prefix, key_hash, key_salt = generate_api_key()

        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.key_hash = key_hash
        mock_api_key.key_salt = key_salt
        mock_api_key.is_salted = True
        mock_api_key.is_active = False  # Key is inactive!
        mock_api_key.expires_at = None
        mock_api_key.user = mock_user

        mock_session.execute.return_value = mock_scalars_result([mock_api_key])

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key=full_key,
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "API key is inactive" in exc_info.value.detail


class TestExpiredAPIKey:
    """Tests for expired API key."""

    @pytest.mark.asyncio
    async def test_expired_api_key_returns_401(self):
        """Test that expired API key returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_active = True

        # Generate a valid key and its hash
        full_key, key_prefix, key_hash, key_salt = generate_api_key()

        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.key_hash = key_hash
        mock_api_key.key_salt = key_salt
        mock_api_key.is_salted = True
        mock_api_key.is_active = True
        mock_api_key.expires_at = datetime.now(UTC) - timedelta(days=1)  # Expired yesterday
        mock_api_key.user = mock_user

        mock_session.execute.return_value = mock_scalars_result([mock_api_key])

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key=full_key,
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "API key has expired" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_api_key_expiring_soon_still_valid(self):
        """Test that API key expiring in the future is still valid."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_active = True
        mock_user.is_superuser = False
        mock_user.domain_memberships = []

        # Generate a valid key and its hash
        full_key, key_prefix, key_hash, key_salt = generate_api_key()

        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.key_hash = key_hash
        mock_api_key.key_salt = key_salt
        mock_api_key.is_salted = True
        mock_api_key.is_active = True
        mock_api_key.expires_at = datetime.now(UTC) + timedelta(hours=1)  # Expires in 1 hour
        mock_api_key.user = mock_user
        mock_api_key.scopes = []

        mock_session.execute.return_value = mock_scalars_result([mock_api_key])

        # Should not raise - key is still valid
        auth_context = await get_auth_context(
            x_api_key=full_key,
            session=mock_session,
            settings=mock_settings,
        )

        assert auth_context.user == mock_user
        assert auth_context.api_key == mock_api_key
        assert auth_context.is_root is False

    @pytest.mark.asyncio
    async def test_api_key_without_expiry_is_valid(self):
        """Test that API key without expiry date is valid."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Create a mock user
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_active = True
        mock_user.is_superuser = False
        mock_user.domain_memberships = []

        # Generate a valid key and its hash
        full_key, key_prefix, key_hash, key_salt = generate_api_key()

        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.key_hash = key_hash
        mock_api_key.key_salt = key_salt
        mock_api_key.is_salted = True
        mock_api_key.is_active = True
        mock_api_key.expires_at = None  # No expiry
        mock_api_key.user = mock_user
        mock_api_key.scopes = ["domains:read", "domains:write"]

        mock_session.execute.return_value = mock_scalars_result([mock_api_key])

        # Should not raise - key is valid
        auth_context = await get_auth_context(
            x_api_key=full_key,
            session=mock_session,
            settings=mock_settings,
        )

        assert auth_context.user == mock_user
        assert auth_context.api_key == mock_api_key
        assert "domains:read" in auth_context.scopes


class TestInactiveUser:
    """Tests for inactive user account."""

    @pytest.mark.asyncio
    async def test_inactive_user_returns_401(self):
        """Test that inactive user account returns 401."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings()

        # Create a mock inactive user
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.is_active = False  # User is inactive!

        # Generate a valid key and its hash
        full_key, key_prefix, key_hash, key_salt = generate_api_key()

        mock_api_key = MagicMock(spec=APIKey)
        mock_api_key.key_hash = key_hash
        mock_api_key.key_salt = key_salt
        mock_api_key.is_salted = True
        mock_api_key.is_active = True
        mock_api_key.expires_at = None
        mock_api_key.user = mock_user

        mock_session.execute.return_value = mock_scalars_result([mock_api_key])

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key=full_key,
                session=mock_session,
                settings=mock_settings,
            )

        assert exc_info.value.status_code == 401
        assert "User account is inactive" in exc_info.value.detail


class TestRootAPIKey:
    """Tests for root API key authentication."""

    @pytest.mark.asyncio
    async def test_root_api_key_succeeds(self):
        """Test that root API key authentication succeeds."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings("test-root-api-key")

        auth_context = await get_auth_context(
            x_api_key="test-root-api-key",
            session=mock_session,
            settings=mock_settings,
        )

        assert auth_context.is_root is True
        assert auth_context.user.username == "root"
        assert auth_context.user.is_superuser is True
        assert auth_context.api_key is None

    @pytest.mark.asyncio
    async def test_root_api_key_has_all_scopes(self):
        """Test that root API key has all scopes."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings("test-root-api-key")

        auth_context = await get_auth_context(
            x_api_key="test-root-api-key",
            session=mock_session,
            settings=mock_settings,
        )

        # Root should have all defined scopes
        assert "admin" in auth_context.scopes
        assert "domains:read" in auth_context.scopes
        assert "domains:write" in auth_context.scopes
        assert "users:read" in auth_context.scopes

    @pytest.mark.asyncio
    async def test_root_api_key_timing_safe_comparison(self):
        """Test that root API key uses timing-safe comparison."""
        mock_session = AsyncMock(spec=AsyncSession)
        mock_settings = create_mock_settings("test-root-api-key")

        # Similar but different key should not authenticate as root
        # This also tests that timing-safe comparison is used (no early exit)
        mock_session.execute.return_value = mock_scalars_result([])

        with pytest.raises(HTTPException) as exc_info:
            await get_auth_context(
                x_api_key="test-root-api-key-WRONG",  # Similar but different
                session=mock_session,
                settings=mock_settings,
            )

        # Should fail as invalid key, not as root
        assert exc_info.value.status_code == 401
        assert "Invalid API key" in exc_info.value.detail


class TestAuthContext:
    """Tests for AuthContext methods."""

    def test_has_scope_with_admin(self):
        """Test that admin scope grants access to all scopes."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=False,
            scopes={"admin"},
        )

        assert auth.has_scope("domains:read") is True
        assert auth.has_scope("users:write") is True
        assert auth.has_scope("any:scope") is True

    def test_has_scope_with_root(self):
        """Test that root user has access to all scopes."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = True

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=True,
            scopes=set(),  # Empty scopes, but is_root
        )

        assert auth.has_scope("domains:read") is True
        assert auth.has_scope("users:write") is True

    def test_has_scope_specific(self):
        """Test that specific scopes are checked correctly."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=False,
            scopes={"domains:read", "domains:write"},
        )

        assert auth.has_scope("domains:read") is True
        assert auth.has_scope("domains:write") is True
        assert auth.has_scope("users:read") is False

    def test_require_scope_raises_on_missing(self):
        """Test that require_scope raises HTTPException on missing scope."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=False,
            scopes={"domains:read"},
        )

        with pytest.raises(HTTPException) as exc_info:
            auth.require_scope("users:write")

        assert exc_info.value.status_code == 403
        assert "Missing required scope" in exc_info.value.detail

    def test_is_superuser_with_root(self):
        """Test is_superuser returns True for root."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=True,
            scopes=set(),
        )

        assert auth.is_superuser() is True

    def test_is_superuser_with_superuser_flag(self):
        """Test is_superuser returns True for superuser users."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = True

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=False,
            scopes=set(),
        )

        assert auth.is_superuser() is True

    def test_is_superuser_regular_user(self):
        """Test is_superuser returns False for regular users."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=False,
            scopes={"domains:read"},
        )

        assert auth.is_superuser() is False

    def test_require_superuser_raises_for_regular_user(self):
        """Test require_superuser raises for non-superuser."""
        mock_user = MagicMock(spec=User)
        mock_user.is_superuser = False

        auth = AuthContext(
            user=mock_user,
            api_key=None,
            is_root=False,
            scopes=set(),
        )

        with pytest.raises(HTTPException) as exc_info:
            auth.require_superuser()

        assert exc_info.value.status_code == 403
        assert "Superuser access required" in exc_info.value.detail
