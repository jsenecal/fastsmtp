"""Authentication and API key management commands."""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.output import (
    print_api_key,
    print_api_keys_table,
    print_error,
    print_success,
    print_whoami,
)

app = typer.Typer(help="Authentication and API key management")


@app.command("whoami")
def whoami(
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Show current authenticated user info."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            result = client.whoami()
            print_whoami(result)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("keys")
def list_keys(
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List your API keys."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            keys = client.list_api_keys()
            if not keys:
                print_error("No API keys found")
                return
            print_api_keys_table(keys)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("create-key")
def create_key(
    name: Annotated[str, typer.Argument(help="Key name")],
    scopes: Annotated[
        list[str] | None,
        typer.Option("--scope", "-s", help="Scopes for the key (can be repeated)"),
    ] = None,
    expires: Annotated[
        int | None,
        typer.Option("--expires", "-e", help="Days until expiration"),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new API key."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            result = client.create_api_key(name=name, scopes=scopes, expires_days=expires)
            print_api_key(result, show_secret=True)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("delete-key")
def delete_key(
    key_id: Annotated[str, typer.Argument(help="Key ID to delete")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Delete an API key."""
    if not force:
        confirm = typer.confirm(f"Delete API key {key_id}?")
        if not confirm:
            raise typer.Exit(0)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_api_key(key_id)
            print_success(f"API key {key_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("rotate-key")
def rotate_key(
    key_id: Annotated[str, typer.Argument(help="Key ID to rotate")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Rotate an API key (generates new secret)."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            result = client.rotate_api_key(key_id)
            print_api_key(result, show_secret=True)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
