"""Domain and member management commands."""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.output import (
    print_domain,
    print_domains_table,
    print_error,
    print_members_table,
    print_success,
)

app = typer.Typer(help="Domain management")


@app.command("list")
def list_domains(
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max results")] = 50,
    offset: Annotated[int, typer.Option("--offset", "-o", help="Offset")] = 0,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List domains you have access to."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            domains = client.list_domains(limit=limit, offset=offset)
            if not domains:
                print_error("No domains found")
                return
            print_domains_table(domains)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("get")
def get_domain(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get domain details."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            domain = client.get_domain(domain_id)
            print_domain(domain)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("create")
def create_domain(
    domain_name: Annotated[str, typer.Argument(help="Domain name (e.g., example.com)")],
    description: Annotated[
        str | None,
        typer.Option("--description", "-d", help="Description"),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new domain."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            domain = client.create_domain(domain_name=domain_name, description=description)
            print_success(f"Domain '{domain_name}' created")
            print_domain(domain)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("update")
def update_domain(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    description: Annotated[
        str | None,
        typer.Option("--description", "-d", help="Description"),
    ] = None,
    enabled: Annotated[
        bool | None,
        typer.Option("--enabled/--disabled", help="Enable or disable domain"),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a domain."""
    if description is None and enabled is None:
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            domain = client.update_domain(
                domain_id=domain_id,
                description=description,
                is_enabled=enabled,
            )
            print_success("Domain updated")
            print_domain(domain)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("delete")
def delete_domain(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Delete a domain."""
    if not force:
        confirm = typer.confirm(f"Delete domain {domain_id}?")
        if not confirm:
            raise typer.Exit(0)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_domain(domain_id)
            print_success(f"Domain {domain_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


# Member subcommands
member_app = typer.Typer(help="Domain member management")
app.add_typer(member_app, name="member")


@member_app.command("list")
def list_members(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max results")] = 50,
    offset: Annotated[int, typer.Option("--offset", "-o", help="Offset")] = 0,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List domain members."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            members = client.list_members(domain_id, limit=limit, offset=offset)
            if not members:
                print_error("No members found")
                return
            print_members_table(members)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@member_app.command("add")
def add_member(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    user_id: Annotated[str, typer.Argument(help="User ID to add")],
    role: Annotated[
        str,
        typer.Option("--role", "-r", help="Role (owner, admin, member)"),
    ] = "member",
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Add a member to a domain."""
    if role not in ("owner", "admin", "member"):
        print_error("Role must be one of: owner, admin, member")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.add_member(domain_id, user_id, role=role)
            print_success(f"User {user_id} added to domain as {role}")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@member_app.command("update")
def update_member(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    user_id: Annotated[str, typer.Argument(help="User ID")],
    role: Annotated[str, typer.Option("--role", "-r", help="New role", prompt=True)],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a member's role."""
    if role not in ("owner", "admin", "member"):
        print_error("Role must be one of: owner, admin, member")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.update_member(domain_id, user_id, role=role)
            print_success(f"Member role updated to {role}")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@member_app.command("remove")
def remove_member(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    user_id: Annotated[str, typer.Argument(help="User ID to remove")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Remove a member from a domain."""
    if not force:
        confirm = typer.confirm(f"Remove user {user_id} from domain?")
        if not confirm:
            raise typer.Exit(0)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.remove_member(domain_id, user_id)
            print_success(f"User {user_id} removed from domain")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
