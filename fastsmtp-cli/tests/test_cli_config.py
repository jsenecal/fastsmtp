"""Tests for CLI configuration management."""

import os
import stat
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from fastsmtp_cli import config as config_module
from fastsmtp_cli.config import (
    CLIConfig,
    Profile,
    delete_profile,
    get_config_path,
    get_profile,
    list_profiles,
    load_config,
    save_config,
    set_default_profile,
    set_profile,
)


@pytest.fixture
def temp_config_dir(monkeypatch):
    """Create a temporary config directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = Path(tmpdir) / "config.toml"
        monkeypatch.setenv("FSMTP_CONFIG", str(config_path))
        yield config_path


class TestProfile:
    """Tests for Profile model."""

    def test_profile_defaults(self):
        """Test profile default values."""
        profile = Profile()
        assert profile.url == "http://localhost:8000"
        assert profile.api_key is None
        assert profile.timeout == 30.0
        assert profile.verify_ssl is True

    def test_profile_custom_values(self):
        """Test profile with custom values."""
        profile = Profile(
            url="https://api.example.com",
            api_key="test_key",
            timeout=60.0,
            verify_ssl=False,
        )
        assert profile.url == "https://api.example.com"
        assert profile.api_key == "test_key"
        assert profile.timeout == 60.0
        assert profile.verify_ssl is False


class TestCLIConfig:
    """Tests for CLIConfig model."""

    def test_config_defaults(self):
        """Test config default values."""
        config = CLIConfig()
        assert config.default_profile == "default"
        assert "default" in config.profiles

    def test_config_multiple_profiles(self):
        """Test config with multiple profiles."""
        config = CLIConfig(
            default_profile="prod",
            profiles={
                "default": Profile(),
                "prod": Profile(url="https://prod.example.com"),
                "staging": Profile(url="https://staging.example.com"),
            },
        )
        assert len(config.profiles) == 3
        assert config.default_profile == "prod"


class TestConfigOperations:
    """Tests for config file operations."""

    def test_save_and_load_config(self, temp_config_dir):
        """Test saving and loading config."""
        config = CLIConfig(
            default_profile="test",
            profiles={
                "test": Profile(url="https://test.example.com"),
            },
        )
        save_config(config)

        loaded = load_config()
        assert loaded.default_profile == "test"
        assert loaded.profiles["test"].url == "https://test.example.com"

    def test_load_nonexistent_config(self, temp_config_dir):
        """Test loading nonexistent config returns defaults."""
        config = load_config()
        assert config.default_profile == "default"

    def test_get_config_path_env(self, monkeypatch):
        """Test config path from environment variable."""
        monkeypatch.setenv("FSMTP_CONFIG", "/custom/path/config.toml")
        assert get_config_path() == Path("/custom/path/config.toml")


class TestConfigPermissions:
    """The config file holds API keys in clear, so it must not be readable by others.

    The convention every comparable tool follows - ``~/.aws/credentials``,
    ``~/.docker/config.json``, ``~/.netrc`` - is 0600 on the file and 0700 on the
    directory. Relying on the user's umask is not enough: the common 022 leaves the
    file world-readable.
    """

    def test_saved_config_is_not_readable_by_others(self, temp_config_dir):
        """A freshly written config must be 0600."""
        save_config(CLIConfig(profiles={"p": Profile(api_key="fsmtp_secret")}))

        mode = temp_config_dir.stat().st_mode
        assert mode & 0o077 == 0, f"config is group/world accessible: {stat.filemode(mode)}"

    def test_created_config_dir_is_not_readable_by_others(self, monkeypatch, tmp_path):
        """A config directory created by save_config must be 0700."""
        config_path = tmp_path / "fresh" / "config.toml"
        monkeypatch.setenv("FSMTP_CONFIG", str(config_path))

        save_config(CLIConfig(profiles={"p": Profile(api_key="fsmtp_secret")}))

        mode = config_path.parent.stat().st_mode
        assert mode & 0o077 == 0, f"config dir is group/world accessible: {stat.filemode(mode)}"

    def test_existing_loose_config_is_tightened_on_save(self, temp_config_dir):
        """A config left world-readable by an older version is repaired on the next save.

        Someone whose key already leaked through a 0644 file should not have to
        notice and chmod it themselves.
        """
        temp_config_dir.write_text("default_profile = 'default'\n")
        temp_config_dir.chmod(0o644)

        save_config(CLIConfig(profiles={"p": Profile(api_key="fsmtp_secret")}))

        mode = temp_config_dir.stat().st_mode
        assert mode & 0o077 == 0, f"config left permissive: {stat.filemode(mode)}"

    def test_key_is_never_written_through_a_readable_window(self, temp_config_dir):
        """The file must already be 0600 at the moment the key is written into it.

        Writing first and chmod-ing after leaves a window in which the key sits on
        disk world-readable, so the mode has to be in place before the content is.
        This checks the handle being written to, whichever call opened it.
        """
        observed: list[int] = []
        real_dump = config_module.tomli_w.dump

        def spy(data, fp, *args, **kwargs):
            observed.append(os.fstat(fp.fileno()).st_mode)
            return real_dump(data, fp, *args, **kwargs)

        with mock.patch.object(config_module.tomli_w, "dump", spy):
            save_config(CLIConfig(profiles={"p": Profile(api_key="fsmtp_secret")}))

        assert observed, "config was never written"
        for mode in observed:
            assert mode & 0o077 == 0, (
                f"key written into a group/world accessible file: {stat.filemode(mode)}"
            )


class TestProfileManagement:
    """Tests for profile management functions."""

    def test_set_profile_new(self, temp_config_dir):
        """Test creating a new profile."""
        set_profile("test", url="https://test.example.com")

        profiles = list_profiles()
        assert "test" in profiles
        assert profiles["test"].url == "https://test.example.com"

    def test_set_profile_update(self, temp_config_dir):
        """Test updating an existing profile."""
        set_profile("test", url="https://test.example.com")
        set_profile("test", api_key="new_key")

        profiles = list_profiles()
        assert profiles["test"].url == "https://test.example.com"
        assert profiles["test"].api_key == "new_key"

    def test_delete_profile(self, temp_config_dir):
        """Test deleting a profile."""
        set_profile("test", url="https://test.example.com")
        assert delete_profile("test") is True

        profiles = list_profiles()
        assert "test" not in profiles

    def test_delete_nonexistent_profile(self, temp_config_dir):
        """Test deleting nonexistent profile."""
        assert delete_profile("nonexistent") is False

    def test_set_default_profile(self, temp_config_dir):
        """Test setting default profile."""
        set_profile("prod", url="https://prod.example.com")
        assert set_default_profile("prod") is True

        config = load_config()
        assert config.default_profile == "prod"

    def test_set_default_nonexistent(self, temp_config_dir):
        """Test setting nonexistent profile as default."""
        assert set_default_profile("nonexistent") is False


class TestGetProfile:
    """Tests for get_profile with environment overrides."""

    def test_get_profile_default(self, temp_config_dir):
        """Test getting default profile."""
        profile = get_profile()
        assert profile.url == "http://localhost:8000"

    def test_get_profile_named(self, temp_config_dir):
        """Test getting named profile."""
        set_profile("test", url="https://test.example.com")
        profile = get_profile("test")
        assert profile.url == "https://test.example.com"

    def test_get_profile_env_override_url(self, temp_config_dir, monkeypatch):
        """Test environment variable overrides URL."""
        monkeypatch.setenv("FSMTP_URL", "https://env.example.com")
        profile = get_profile()
        assert profile.url == "https://env.example.com"

    def test_get_profile_env_override_api_key(self, temp_config_dir, monkeypatch):
        """Test environment variable overrides API key."""
        monkeypatch.setenv("FSMTP_API_KEY", "env_api_key")
        profile = get_profile()
        assert profile.api_key == "env_api_key"

    def test_get_profile_env_select_profile(self, temp_config_dir, monkeypatch):
        """Test FSMTP_PROFILE selects profile."""
        set_profile("test", url="https://test.example.com")
        monkeypatch.setenv("FSMTP_PROFILE", "test")
        profile = get_profile()
        assert profile.url == "https://test.example.com"
