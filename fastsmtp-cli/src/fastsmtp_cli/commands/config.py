"""CLI configuration commands."""

from typing import Annotated

import typer

from fastsmtp_cli import config as cfg
from fastsmtp_cli.output import (
    console,
    print_error,
    print_profiles_table,
    print_success,
)

app = typer.Typer(help="Manage CLI configuration and profiles")


@app.command("show")
def show_config(
    show_keys: Annotated[
        bool,
        typer.Option("--show-keys", "-k", help="Show API keys in output"),
    ] = False,
) -> None:
    """Show current configuration."""
    profiles = cfg.list_profiles()
    default = cfg.get_default_profile_name()

    if not profiles:
        console.print("[dim]No profiles configured[/dim]")
        return

    print_profiles_table(profiles, default, show_keys=show_keys)
    console.print(f"\n[dim]Config file: {cfg.get_config_path()}[/dim]")


@app.command("set")
def set_profile(
    name: Annotated[str, typer.Argument(help="Profile name")],
    url: Annotated[
        str | None,
        typer.Option("--url", "-u", help="Server URL"),
    ] = None,
    api_key: Annotated[
        str | None,
        typer.Option("--api-key", "-k", help="API key"),
    ] = None,
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", "-t", help="Request timeout in seconds"),
    ] = None,
    verify_ssl: Annotated[
        bool | None,
        typer.Option("--verify-ssl/--no-verify-ssl", help="Verify SSL certificates"),
    ] = None,
) -> None:
    """Create or update a profile."""
    if url is None and api_key is None and timeout is None and verify_ssl is None:
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    cfg.set_profile(
        name=name,
        url=url,
        api_key=api_key,
        timeout=timeout,
        verify_ssl=verify_ssl,
    )
    print_success(f"Profile '{name}' updated")


@app.command("delete")
def delete_profile(
    name: Annotated[str, typer.Argument(help="Profile name to delete")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
) -> None:
    """Delete a profile."""
    if not force:
        confirm = typer.confirm(f"Delete profile '{name}'?")
        if not confirm:
            raise typer.Exit(0)

    if cfg.delete_profile(name):
        print_success(f"Profile '{name}' deleted")
    else:
        print_error(f"Profile '{name}' not found")
        raise typer.Exit(1)


@app.command("use")
def use_profile(
    name: Annotated[str, typer.Argument(help="Profile name to set as default")],
) -> None:
    """Set the default profile."""
    if cfg.set_default_profile(name):
        print_success(f"Default profile set to '{name}'")
    else:
        print_error(f"Profile '{name}' not found")
        raise typer.Exit(1)


@app.command("init")
def init_config(
    url: Annotated[
        str,
        typer.Option("--url", "-u", help="Server URL", prompt=True),
    ] = "http://localhost:8000",
    api_key: Annotated[
        str | None,
        typer.Option("--api-key", "-k", help="API key"),
    ] = None,
    profile: Annotated[
        str,
        typer.Option("--profile", "-p", help="Profile name"),
    ] = "default",
) -> None:
    """Initialize CLI configuration."""
    config_path = cfg.get_config_path()

    if config_path.exists() and not typer.confirm("Configuration already exists. Overwrite?"):
        raise typer.Exit(0)

    cfg.set_profile(name=profile, url=url, api_key=api_key)
    cfg.set_default_profile(profile)

    print_success(f"Configuration saved to {config_path}")
    console.print(f"\nProfile '{profile}' created with URL: {url}")

    if not api_key:
        console.print(
            "\n[yellow]Note:[/yellow] No API key configured. "
            "Set one with: fsmtp config set default --api-key YOUR_KEY"
        )
