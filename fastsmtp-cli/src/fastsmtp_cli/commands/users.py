"""User management commands (superuser only).

The server's ``UserCreate`` requires only ``username`` and additionally accepts
``email`` and ``is_superuser``; ``UserUpdate`` accepts ``username``, ``email``,
``is_active`` and ``is_superuser``. Neither carries a password - accounts
authenticate with API keys (``fsmtp auth create-key``) - so no command here
offers one. ``GET /api/v1/users`` declares no query parameters, so ``list``
takes none either.
"""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.output import (
    print_error,
    print_success,
    print_user,
    print_users_table,
)

app = typer.Typer(help="User management (superuser only)")

ProfileOption = Annotated[
    str | None,
    typer.Option("--profile", "-p", help="Profile to use"),
]


@app.command("list")
def list_users(profile: ProfileOption = None) -> None:
    """List all users."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            users = client.list_users()
            if not users:
                print_error("No users found")
                return
            print_users_table(users)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("get")
def get_user(
    user_id: Annotated[str, typer.Argument(help="User ID")],
    profile: ProfileOption = None,
) -> None:
    """Get user details."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            user = client.get_user(user_id)
            print_user(user)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("create")
def create_user(
    username: Annotated[str, typer.Argument(help="Username")],
    email: Annotated[
        str | None,
        typer.Option("--email", "-e", help="Email address"),
    ] = None,
    superuser: Annotated[
        bool,
        typer.Option("--superuser", help="Grant superuser privileges"),
    ] = False,
    profile: ProfileOption = None,
) -> None:
    """Create a new user."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            user = client.create_user(username=username, email=email, is_superuser=superuser)
            print_success(f"User '{username}' created")
            print_user(user)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("update")
def update_user(
    user_id: Annotated[str, typer.Argument(help="User ID")],
    username: Annotated[
        str | None,
        typer.Option("--username", "-u", help="New username"),
    ] = None,
    email: Annotated[
        str | None,
        typer.Option("--email", "-e", help="New email address"),
    ] = None,
    active: Annotated[
        bool | None,
        typer.Option("--active/--inactive", help="Activate or deactivate the account"),
    ] = None,
    superuser: Annotated[
        bool | None,
        typer.Option("--superuser/--no-superuser", help="Grant or revoke superuser privileges"),
    ] = None,
    profile: ProfileOption = None,
) -> None:
    """Update a user."""
    if all(value is None for value in (username, email, active, superuser)):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            user = client.update_user(
                user_id=user_id,
                username=username,
                email=email,
                is_active=active,
                is_superuser=superuser,
            )
            print_success("User updated")
            print_user(user)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("delete")
def delete_user(
    user_id: Annotated[str, typer.Argument(help="User ID")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    profile: ProfileOption = None,
) -> None:
    """Delete a user."""
    if not force:
        confirm = typer.confirm(f"Delete user {user_id}?")
        if not confirm:
            raise typer.Exit(0)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_user(user_id)
            print_success(f"User {user_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
