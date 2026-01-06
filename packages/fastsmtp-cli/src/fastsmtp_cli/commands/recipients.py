"""Recipient management commands."""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.output import (
    print_error,
    print_recipient,
    print_recipients_table,
    print_success,
)

app = typer.Typer(help="Recipient management")


@app.command("list")
def list_recipients(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max results")] = 50,
    offset: Annotated[int, typer.Option("--offset", "-o", help="Offset")] = 0,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List recipients for a domain."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipients = client.list_recipients(domain_id, limit=limit, offset=offset)
            if not recipients:
                print_error("No recipients found")
                return
            print_recipients_table(recipients)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("get")
def get_recipient(
    recipient_id: Annotated[str, typer.Argument(help="Recipient ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get recipient details."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipient = client.get_recipient(recipient_id)
            print_recipient(recipient)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("create")
def create_recipient(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    webhook_url: Annotated[str, typer.Argument(help="Webhook URL")],
    local_part: Annotated[
        str | None,
        typer.Option("--local", "-l", help="Local part (omit for catch-all)"),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", "-d", help="Description"),
    ] = None,
    tags: Annotated[
        list[str] | None,
        typer.Option("--tag", "-t", help="Tags (can be repeated)"),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new recipient."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipient = client.create_recipient(
                domain_id=domain_id,
                webhook_url=webhook_url,
                local_part=local_part,
                description=description,
                tags=tags,
            )
            address = local_part if local_part else "* (catch-all)"
            print_success(f"Recipient '{address}' created")
            print_recipient(recipient)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("update")
def update_recipient(
    recipient_id: Annotated[str, typer.Argument(help="Recipient ID")],
    local_part: Annotated[
        str | None,
        typer.Option("--local", "-l", help="Local part"),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook", "-w", help="Webhook URL"),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", "-d", help="Description"),
    ] = None,
    enabled: Annotated[
        bool | None,
        typer.Option("--enabled/--disabled", help="Enable or disable recipient"),
    ] = None,
    tags: Annotated[
        list[str] | None,
        typer.Option("--tag", "-t", help="Tags (replaces existing)"),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a recipient."""
    if all(
        v is None for v in [local_part, webhook_url, description, enabled, tags]
    ):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipient = client.update_recipient(
                recipient_id=recipient_id,
                local_part=local_part,
                webhook_url=webhook_url,
                description=description,
                is_enabled=enabled,
                tags=tags,
            )
            print_success("Recipient updated")
            print_recipient(recipient)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("delete")
def delete_recipient(
    recipient_id: Annotated[str, typer.Argument(help="Recipient ID")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Delete a recipient."""
    if not force:
        confirm = typer.confirm(f"Delete recipient {recipient_id}?")
        if not confirm:
            raise typer.Exit(0)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_recipient(recipient_id)
            print_success(f"Recipient {recipient_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
