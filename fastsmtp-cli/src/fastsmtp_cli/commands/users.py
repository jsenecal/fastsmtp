"""User management commands (superuser only).

The server's ``UserCreate`` requires only ``username`` and additionally accepts
``email`` and ``is_superuser``; ``UserUpdate`` accepts ``username``, ``email``,
``is_active`` and ``is_superuser``. Neither carries a password - accounts
authenticate with API keys (``fsmtp auth create-key``) - so no command here
offers one. The only query parameter on ``GET /api/v1/users`` and
``GET /api/v1/users/{id}`` is ``include_deleted``, exposed as
``--include-deleted``.

``delete`` is a soft delete: the user disappears from every listing and can
no longer authenticate, but ``restore`` brings the account and its domain
memberships back. The API keys revoked at deletion are never restored.
``delete --purge`` removes an already-deleted user for good.
"""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.commands.options import IncludeDeleted, Purge, clearable_str, confirm_delete
from fastsmtp_cli.output import (
    print_deleted,
    print_error,
    print_info,
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
def list_users(include_deleted: IncludeDeleted = False, profile: ProfileOption = None) -> None:
    """List all users."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            users = client.list_users(include_deleted=include_deleted)
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
    include_deleted: IncludeDeleted = False,
    profile: ProfileOption = None,
) -> None:
    """Get user details (a deleted user is not found without --include-deleted)."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            user = client.get_user(user_id, include_deleted=include_deleted)
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
        typer.Option("--email", "-e", help="New email address; pass '' to clear it"),
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
                email=clearable_str(email),
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
    purge: Purge = False,
    profile: ProfileOption = None,
) -> None:
    """Delete a user (restorable), or permanently purge an already-deleted one."""
    confirm_delete("user", user_id, force=force, purge=purge)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_user(user_id, purge=purge)
            print_deleted(
                "user", user_id, purge=purge, restore_command=f"fsmtp users restore {user_id}"
            )
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("restore")
def restore_user(
    user_id: Annotated[str, typer.Argument(help="User ID")],
    profile: ProfileOption = None,
) -> None:
    """Restore a deleted user and their domain memberships.

    API keys revoked at deletion stay revoked; create new ones afterwards.
    """
    try:
        with FastSMTPClient(profile_name=profile) as client:
            user = client.restore_user(user_id)
            print_success("User restored")
            print_user(user)
            print_info("API keys revoked at deletion are not restored; create new keys.")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
