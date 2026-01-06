"""Operations commands (health, logs, test webhook)."""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.output import (
    print_delivery_log,
    print_delivery_logs_table,
    print_error,
    print_health,
    print_ready,
    print_success,
    print_test_webhook_result,
)

app = typer.Typer(help="Operations (health, logs, test)")


@app.command("health")
def health(
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Check server health."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            result = client.health()
            print_health(result)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("ready")
def ready(
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Check server readiness (includes database check)."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            result = client.ready()
            print_ready(result)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


# Delivery log commands
log_app = typer.Typer(help="Delivery log management")
app.add_typer(log_app, name="log")


@log_app.command("list")
def list_logs(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    status: Annotated[
        str | None,
        typer.Option("--status", "-s", help="Filter by status"),
    ] = None,
    message_id: Annotated[
        str | None,
        typer.Option("--message-id", "-m", help="Filter by message ID"),
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max results")] = 50,
    offset: Annotated[int, typer.Option("--offset", "-o", help="Offset")] = 0,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List delivery logs for a domain."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            logs = client.list_delivery_logs(
                domain_id,
                status=status,
                message_id=message_id,
                limit=limit,
                offset=offset,
            )
            if not logs:
                print_error("No delivery logs found")
                return
            print_delivery_logs_table(logs)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@log_app.command("get")
def get_log(
    log_id: Annotated[str, typer.Argument(help="Delivery log ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get delivery log details with payload."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            log = client.get_delivery_log(log_id)
            print_delivery_log(log)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@log_app.command("retry")
def retry_log(
    log_id: Annotated[str, typer.Argument(help="Delivery log ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Retry a failed delivery."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            result = client.retry_delivery(log_id)
            print_success(result.get("message", "Delivery queued for retry"))
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


# Test webhook command
@app.command("test-webhook")
def test_webhook(
    webhook_url: Annotated[str, typer.Argument(help="Webhook URL to test")],
    from_addr: Annotated[
        str,
        typer.Option("--from", "-f", help="From address"),
    ] = "test@example.com",
    to_addr: Annotated[
        str,
        typer.Option("--to", "-t", help="To address"),
    ] = "recipient@example.com",
    subject: Annotated[
        str,
        typer.Option("--subject", "-s", help="Subject"),
    ] = "Test Email",
    body: Annotated[
        str,
        typer.Option("--body", "-b", help="Body text"),
    ] = "This is a test email from FastSMTP.",
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Test a webhook URL by sending a test payload."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            result = client.test_webhook(
                webhook_url=webhook_url,
                from_address=from_addr,
                to_address=to_addr,
                subject=subject,
                body=body,
            )
            print_test_webhook_result(result)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
