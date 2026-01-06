"""CLI configuration management with profiles."""

import contextlib
import os
from pathlib import Path
from typing import Any

import tomli_w

try:
    import tomllib
except ImportError:
    import tomli as tomllib

from pydantic import BaseModel, Field

DEFAULT_CONFIG_DIR = Path.home() / ".fastsmtp"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.toml"


class Profile(BaseModel):
    """A server profile configuration."""

    url: str = Field(default="http://localhost:8000", description="Server URL")
    api_key: str | None = Field(default=None, description="API key for authentication")
    timeout: float = Field(default=30.0, description="Request timeout in seconds")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates")


class CLIConfig(BaseModel):
    """CLI configuration with multiple profiles."""

    default_profile: str = Field(default="default", description="Default profile name")
    profiles: dict[str, Profile] = Field(
        default_factory=lambda: {"default": Profile()},
        description="Server profiles",
    )


def get_config_path() -> Path:
    """Get the configuration file path."""
    # Check environment variable first
    env_path = os.environ.get("FSMTP_CONFIG")
    if env_path:
        return Path(env_path)
    return DEFAULT_CONFIG_FILE


def load_config() -> CLIConfig:
    """Load configuration from file."""
    config_path = get_config_path()

    if not config_path.exists():
        return CLIConfig()

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return CLIConfig.model_validate(data)
    except Exception:
        # If config is corrupted, return default
        return CLIConfig()


def save_config(config: CLIConfig) -> None:
    """Save configuration to file."""
    config_path = get_config_path()

    # Ensure directory exists
    config_path.parent.mkdir(parents=True, exist_ok=True)

    # Exclude None values from the dump (TOML can't serialize None)
    with open(config_path, "wb") as f:
        tomli_w.dump(config.model_dump(exclude_none=True), f)


def get_profile(profile_name: str | None = None) -> Profile:
    """Get a profile by name, with environment variable overrides.

    Priority (highest to lowest):
    1. Environment variables (FSMTP_URL, FSMTP_API_KEY, etc.)
    2. Named profile from config file
    3. Default profile from config file
    4. Built-in defaults
    """
    config = load_config()

    # Determine which profile to use
    name = profile_name or os.environ.get("FSMTP_PROFILE") or config.default_profile

    # Get base profile
    profile = config.profiles[name] if name in config.profiles else Profile()

    # Apply environment variable overrides
    url = os.environ.get("FSMTP_URL")
    if url:
        profile = profile.model_copy(update={"url": url})

    api_key = os.environ.get("FSMTP_API_KEY")
    if api_key:
        profile = profile.model_copy(update={"api_key": api_key})

    timeout = os.environ.get("FSMTP_TIMEOUT")
    if timeout:
        with contextlib.suppress(ValueError):
            profile = profile.model_copy(update={"timeout": float(timeout)})

    verify_ssl = os.environ.get("FSMTP_VERIFY_SSL")
    if verify_ssl is not None:
        profile = profile.model_copy(
            update={"verify_ssl": verify_ssl.lower() not in ("0", "false", "no")}
        )

    return profile


def set_profile(
    name: str,
    url: str | None = None,
    api_key: str | None = None,
    timeout: float | None = None,
    verify_ssl: bool | None = None,
) -> None:
    """Create or update a profile."""
    config = load_config()

    # Get existing profile or create new one
    if name in config.profiles:
        profile_data = config.profiles[name].model_dump()
    else:
        profile_data: dict[str, Any] = {}

    # Update with provided values
    if url is not None:
        profile_data["url"] = url
    if api_key is not None:
        profile_data["api_key"] = api_key
    if timeout is not None:
        profile_data["timeout"] = timeout
    if verify_ssl is not None:
        profile_data["verify_ssl"] = verify_ssl

    config.profiles[name] = Profile.model_validate(profile_data)
    save_config(config)


def delete_profile(name: str) -> bool:
    """Delete a profile. Returns True if deleted, False if not found."""
    config = load_config()

    if name not in config.profiles:
        return False

    if name == config.default_profile and len(config.profiles) > 1:
        # Can't delete the default profile if there are others
        # Set a different default first
        for other_name in config.profiles:
            if other_name != name:
                config.default_profile = other_name
                break

    del config.profiles[name]

    # Ensure at least one profile exists
    if not config.profiles:
        config.profiles["default"] = Profile()
        config.default_profile = "default"

    save_config(config)
    return True


def set_default_profile(name: str) -> bool:
    """Set the default profile. Returns True if set, False if profile not found."""
    config = load_config()

    if name not in config.profiles:
        return False

    config.default_profile = name
    save_config(config)
    return True


def list_profiles() -> dict[str, Profile]:
    """List all profiles."""
    config = load_config()
    return config.profiles


def get_default_profile_name() -> str:
    """Get the name of the default profile."""
    config = load_config()
    return config.default_profile
