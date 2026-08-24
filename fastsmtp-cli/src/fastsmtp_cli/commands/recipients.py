"""Recipient management commands.

Recipients are nested under a domain on the server, so every command that
addresses a single recipient takes the domain ID as well as the recipient ID.

``delete`` is a soft delete: the address stops receiving mail and its queued
deliveries are cancelled, but ``restore`` brings it back (cancelled deliveries
stay cancelled; re-queue them with ``fsmtp ops log retry``). ``delete
--purge`` removes an already-deleted recipient for good.
"""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.commands.options import IncludeDeleted, Purge, clearable_str, confirm_delete
from fastsmtp_cli.output import (
    print_deleted,
    print_error,
    print_recipient,
    print_recipients_table,
    print_success,
)

app = typer.Typer(help="Recipient management")

HeaderOption = Annotated[
    list[str] | None,
    typer.Option("--header", "-H", help="Webhook header as KEY=VALUE (can be repeated)"),
]


def parse_headers(headers: list[str] | None) -> dict[str, str] | None:
    """Parse repeated ``KEY=VALUE`` options into a headers mapping.

    Raises:
        typer.Exit: with status 1 if an entry is not ``KEY=VALUE``
    """
    if not headers:
        return None
    parsed: dict[str, str] = {}
    for entry in headers:
        key, separator, value = entry.partition("=")
        if not separator or not key.strip():
            print_error(f"Invalid header '{entry}'. Use KEY=VALUE.")
            raise typer.Exit(1)
        parsed[key.strip()] = value.strip()
    return parsed


@app.command("list")
def list_recipients(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    include_deleted: IncludeDeleted = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List recipients for a domain."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipients = client.list_recipients(domain_id, include_deleted=include_deleted)
            if not recipients:
                print_error("No recipients found")
                return
            print_recipients_table(recipients)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("get")
def get_recipient(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    recipient_id: Annotated[str, typer.Argument(help="Recipient ID")],
    include_deleted: IncludeDeleted = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get recipient details (a deleted recipient is not found without --include-deleted)."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipient = client.get_recipient(
                domain_id, recipient_id, include_deleted=include_deleted
            )
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
    headers: HeaderOption = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new recipient."""
    webhook_headers = parse_headers(headers)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipient = client.create_recipient(
                domain_id=domain_id,
                webhook_url=webhook_url,
                local_part=local_part,
                webhook_headers=webhook_headers,
            )
            address = local_part if local_part else "* (catch-all)"
            print_success(f"Recipient '{address}' created")
            print_recipient(recipient)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("update")
def update_recipient(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    recipient_id: Annotated[str, typer.Argument(help="Recipient ID")],
    local_part: Annotated[
        str | None,
        typer.Option("--local", "-l", help="Local part; pass '' to clear it (catch-all)"),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook", "-w", help="Webhook URL"),
    ] = None,
    enabled: Annotated[
        bool | None,
        typer.Option("--enabled/--disabled", help="Enable or disable recipient"),
    ] = None,
    headers: HeaderOption = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a recipient."""
    if all(value is None for value in [local_part, webhook_url, enabled, headers]):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    webhook_headers = parse_headers(headers)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipient = client.update_recipient(
                domain_id=domain_id,
                recipient_id=recipient_id,
                local_part=clearable_str(local_part),
                webhook_url=webhook_url,
                is_enabled=enabled,
                webhook_headers=webhook_headers,
            )
            print_success("Recipient updated")
            print_recipient(recipient)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("delete")
def delete_recipient(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    recipient_id: Annotated[str, typer.Argument(help="Recipient ID")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    purge: Purge = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Delete a recipient (restorable), or permanently purge an already-deleted one."""
    confirm_delete("recipient", recipient_id, force=force, purge=purge)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_recipient(domain_id, recipient_id, purge=purge)
            print_deleted(
                "recipient",
                recipient_id,
                purge=purge,
                restore_command=f"fsmtp recipient restore {domain_id} {recipient_id}",
            )
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("restore")
def restore_recipient(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    recipient_id: Annotated[str, typer.Argument(help="Recipient ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Restore a deleted recipient (the domain itself must not be deleted)."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            recipient = client.restore_recipient(domain_id, recipient_id)
            print_success("Recipient restored")
            print_recipient(recipient)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
