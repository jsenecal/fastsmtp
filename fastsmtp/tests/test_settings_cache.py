"""Tests for settings caching behavior.

Tests follow TDD - written before implementation.
"""


class TestSettingsCacheClearing:
    """Test settings cache clearing functionality."""

    def test_clear_settings_cache_function_exists(self):
        """There should be a function to clear the settings cache."""
        from fastsmtp.config import clear_settings_cache

        # Function should exist and be callable
        assert callable(clear_settings_cache)

    def test_clear_settings_cache_returns_fresh_instance(self):
        """After clearing cache, get_settings returns a new instance."""
        from fastsmtp.config import clear_settings_cache, get_settings

        # Get initial settings
        settings1 = get_settings()

        # Clear cache
        clear_settings_cache()

        # Get settings again - should be a new instance
        settings2 = get_settings()

        # They should be different object instances
        assert settings1 is not settings2

    def test_clear_settings_cache_is_idempotent(self):
        """Clearing cache multiple times should not cause errors."""
        from fastsmtp.config import clear_settings_cache

        # Should not raise any errors
        clear_settings_cache()
        clear_settings_cache()
        clear_settings_cache()

    def test_settings_are_cached_by_default(self):
        """Multiple calls to get_settings should return the same instance."""
        from fastsmtp.config import clear_settings_cache, get_settings

        # Clear cache first to ensure clean state
        clear_settings_cache()

        # Get settings twice
        settings1 = get_settings()
        settings2 = get_settings()

        # Should be the same instance (cached)
        assert settings1 is settings2

    def test_environment_changes_reflected_after_cache_clear(self, monkeypatch):
        """Environment variable changes should be reflected after clearing cache."""
        from fastsmtp.config import clear_settings_cache, get_settings

        # Clear cache first
        clear_settings_cache()

        # Get initial settings
        settings1 = get_settings()
        initial_port = settings1.api_port

        # Clear cache
        clear_settings_cache()

        # Change environment variable
        new_port = 9999
        monkeypatch.setenv("FASTSMTP_API_PORT", str(new_port))

        # Get settings again
        settings2 = get_settings()

        # Should reflect new environment value
        assert settings2.api_port == new_port
        assert settings2.api_port != initial_port

        # Cleanup: clear cache again so other tests aren't affected
        clear_settings_cache()


class TestSettingsCacheTestIsolation:
    """Test that settings cache doesn't leak between tests."""

    def test_cache_clear_in_conftest_fixture(self):
        """Tests should be able to use clear_settings_cache in fixtures."""
        from fastsmtp.config import clear_settings_cache, get_settings

        # This pattern should work in conftest.py fixtures
        clear_settings_cache()
        settings = get_settings()
        assert settings is not None

        # Cleanup
        clear_settings_cache()
