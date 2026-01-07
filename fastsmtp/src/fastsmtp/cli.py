"""FastSMTP server CLI."""

import asyncio
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from fastsmtp import __version__
from fastsmtp.auth.keys import generate_api_key
from fastsmtp.config import get_settings

app = typer.Typer(
    name="fastsmtp",
    help="FastSMTP - SMTP-to-Webhook Relay Server",
    no_args_is_help=True,
)

console = Console()

# Subcommands
db_app = typer.Typer(help="Database management commands")
user_app = typer.Typer(help="User management commands")
domain_app = typer.Typer(help="Domain management commands")

app.add_typer(db_app, name="db")
app.add_typer(user_app, name="user")
app.add_typer(domain_app, name="domain")


def run_async(coro):
    """Run an async function synchronously."""
    return asyncio.run(coro)


@app.command()
def serve(
    smtp_only: bool = typer.Option(False, "--smtp-only", help="Run only SMTP server"),
    api_only: bool = typer.Option(False, "--api-only", help="Run only API server"),
    worker_only: bool = typer.Option(False, "--worker-only", help="Run only webhook worker"),
    shutdown_timeout: int = typer.Option(
        30, "--shutdown-timeout", help="Timeout for graceful shutdown in seconds"
    ),
):
    """Start the FastSMTP server."""
    import signal

    import uvicorn

    from fastsmtp.config import get_settings
    from fastsmtp.smtp import SMTPServer
    from fastsmtp.webhook import WebhookWorker

    settings = get_settings()

    async def run_all():
        # Track all components for graceful shutdown
        smtp_server: SMTPServer | None = None
        uvicorn_server: uvicorn.Server | None = None
        webhook_worker: WebhookWorker | None = None
        cleanup_worker = None
        shutdown_event = asyncio.Event()

        async def graceful_shutdown(sig: signal.Signals | None = None) -> None:
            """Handle graceful shutdown of all components."""
            if sig:
                console.print(f"\n[yellow]Received {sig.name}, shutting down...[/yellow]")
            else:
                console.print("\n[yellow]Shutting down...[/yellow]")

            shutdown_event.set()

            # Stop components in reverse order of startup
            shutdown_tasks = []

            if cleanup_worker is not None:
                shutdown_tasks.append(cleanup_worker.stop())
                console.print("[dim]Stopping cleanup worker...[/dim]")

            if webhook_worker is not None:
                shutdown_tasks.append(webhook_worker.stop())
                console.print("[dim]Stopping webhook worker...[/dim]")

            if uvicorn_server is not None:
                uvicorn_server.should_exit = True
                console.print("[dim]Stopping API server...[/dim]")

            if smtp_server is not None:
                smtp_server.stop()
                console.print("[dim]Stopping SMTP server...[/dim]")

            # Wait for async shutdowns with timeout
            if shutdown_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*shutdown_tasks, return_exceptions=True),
                        timeout=shutdown_timeout,
                    )
                except asyncio.TimeoutError:
                    console.print("[red]Shutdown timed out, forcing exit[/red]")

            console.print("[green]Shutdown complete[/green]")

        # Set up signal handlers
        loop = asyncio.get_running_loop()

        def signal_handler(sig: signal.Signals) -> None:
            """Handle OS signals."""
            loop.create_task(graceful_shutdown(sig))

        # Register signal handlers (Unix only)
        try:
            loop.add_signal_handler(signal.SIGTERM, lambda: signal_handler(signal.SIGTERM))
            loop.add_signal_handler(signal.SIGINT, lambda: signal_handler(signal.SIGINT))
        except NotImplementedError:
            # Windows doesn't support add_signal_handler
            pass

        tasks = []

        if not api_only and not worker_only:
            # Start SMTP server
            smtp_server = SMTPServer(settings)
            smtp_server.start()
            console.print(
                f"[green]SMTP server started on {settings.smtp_host}:{settings.smtp_port}[/green]"
            )

        if not smtp_only and not worker_only:
            # Start API server in a task
            config = uvicorn.Config(
                "fastsmtp.main:app",
                host=settings.api_host,
                port=settings.api_port,
                log_level="info",
            )
            uvicorn_server = uvicorn.Server(config)
            tasks.append(asyncio.create_task(uvicorn_server.serve()))
            console.print(
                f"[green]API server started on {settings.api_host}:{settings.api_port}[/green]"
            )

        if not smtp_only and not api_only:
            # Start webhook worker
            from fastsmtp.cleanup import CleanupWorker

            webhook_worker = WebhookWorker(settings)
            webhook_worker.start()
            console.print("[green]Webhook worker started[/green]")

            # Start cleanup worker (if enabled)
            cleanup_worker = CleanupWorker(settings)
            cleanup_worker.start()
            if settings.delivery_log_cleanup_enabled:
                console.print(
                    f"[green]Cleanup worker started (interval: {settings.delivery_log_cleanup_interval_hours}h)[/green]"
                )

        if tasks:
            # Wait for server tasks or shutdown event
            await asyncio.gather(*tasks)

    try:
        asyncio.run(run_all())
    except KeyboardInterrupt:
        # KeyboardInterrupt is handled by signal handler on Unix
        # On Windows, we catch it here
        console.print("\n[yellow]Interrupted[/yellow]")


@app.command()
def version():
    """Show version information."""
    console.print(f"FastSMTP version {__version__}")


@app.command()
def show_config():
    """Show current configuration."""
    settings = get_settings()

    table = Table(title="FastSMTP Configuration")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    for field_name in settings.model_fields:
        value = getattr(settings, field_name)
        # Hide sensitive values
        if "key" in field_name.lower() or "secret" in field_name.lower():
            value = "********"
        elif isinstance(value, Path):
            value = str(value)
        table.add_row(field_name, str(value))

    console.print(table)


# Database commands


@db_app.command("upgrade")
def db_upgrade(
    revision: str = typer.Argument("head", help="Revision to upgrade to"),
):
    """Upgrade database to a revision."""
    _run_alembic("upgrade", revision)


@db_app.command("downgrade")
def db_downgrade(
    revision: str = typer.Argument(..., help="Revision to downgrade to"),
):
    """Downgrade database to a revision."""
    _run_alembic("downgrade", revision)


@db_app.command("revision")
def db_revision(
    message: str = typer.Option(..., "-m", "--message", help="Revision message"),
    autogenerate: bool = typer.Option(True, "--autogenerate/--no-autogenerate"),
):
    """Create a new database revision."""
    args = ["revision", "-m", message]
    if autogenerate:
        args.append("--autogenerate")
    _run_alembic(*args)


@db_app.command("current")
def db_current():
    """Show current database revision."""
    _run_alembic("current")


@db_app.command("history")
def db_history():
    """Show revision history."""
    _run_alembic("history")


def _run_alembic(*args):
    """Run alembic command."""
    # Find alembic.ini
    package_dir = Path(__file__).parent.parent.parent.parent
    alembic_ini = package_dir / "alembic.ini"

    if not alembic_ini.exists():
        console.print(f"[red]alembic.ini not found at {alembic_ini}[/red]")
        raise typer.Exit(1)

    cmd = ["alembic", "-c", str(alembic_ini), *args]
    result = subprocess.run(cmd, cwd=package_dir)
    if result.returncode != 0:
        raise typer.Exit(result.returncode)


# User commands


@user_app.command("create")
def user_create(
    username: str = typer.Argument(..., help="Username"),
    email: str = typer.Option(None, "--email", "-e", help="Email address"),
    superuser: bool = typer.Option(False, "--superuser", help="Create as superuser"),
):
    """Create a new user."""
    from fastsmtp.db.models import User
    from fastsmtp.db.session import async_session

    async def create():
        async with async_session() as session:
            # Check if user exists
            from sqlalchemy import select

            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            if result.scalar_one_or_none():
                console.print(f"[red]User '{username}' already exists[/red]")
                raise typer.Exit(1)

            user = User(username=username, email=email, is_superuser=superuser)
            session.add(user)
            await session.commit()
            await session.refresh(user)

            console.print(f"[green]Created user '{username}' (ID: {user.id})[/green]")
            if superuser:
                console.print("[yellow]User is a superuser[/yellow]")

    run_async(create())


@user_app.command("list")
def user_list():
    """List all users."""
    from fastsmtp.db.models import User
    from fastsmtp.db.session import async_session

    async def list_users():
        async with async_session() as session:
            from sqlalchemy import select

            stmt = select(User).order_by(User.username)
            result = await session.execute(stmt)
            users = result.scalars().all()

            table = Table(title="Users")
            table.add_column("ID", style="dim")
            table.add_column("Username", style="cyan")
            table.add_column("Email")
            table.add_column("Active")
            table.add_column("Superuser")

            for user in users:
                table.add_row(
                    str(user.id)[:8],
                    user.username,
                    user.email or "",
                    "✓" if user.is_active else "✗",
                    "✓" if user.is_superuser else "✗",
                )

            console.print(table)

    run_async(list_users())


@user_app.command("delete")
def user_delete(
    username: str = typer.Argument(..., help="Username to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a user."""
    from fastsmtp.db.models import User
    from fastsmtp.db.session import async_session

    async def delete():
        async with async_session() as session:
            from sqlalchemy import select

            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                console.print(f"[red]User '{username}' not found[/red]")
                raise typer.Exit(1)

            if not force:
                confirm = typer.confirm(f"Delete user '{username}'?")
                if not confirm:
                    raise typer.Abort()

            await session.delete(user)
            await session.commit()
            console.print(f"[green]Deleted user '{username}'[/green]")

    run_async(delete())


@user_app.command("set-superuser")
def user_set_superuser(
    username: str = typer.Argument(..., help="Username"),
    enable: bool = typer.Option(None, "--enable/--disable", help="Enable or disable superuser"),
):
    """Set or unset superuser status."""
    from fastsmtp.db.models import User
    from fastsmtp.db.session import async_session

    if enable is None:
        console.print("[red]Please specify --enable or --disable[/red]")
        raise typer.Exit(1)

    async def update():
        async with async_session() as session:
            from sqlalchemy import select

            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                console.print(f"[red]User '{username}' not found[/red]")
                raise typer.Exit(1)

            user.is_superuser = enable
            await session.commit()

            status = "enabled" if enable else "disabled"
            console.print(f"[green]Superuser {status} for '{username}'[/green]")

    run_async(update())


@user_app.command("generate-key")
def user_generate_key(
    username: str = typer.Argument(..., help="Username"),
    name: str = typer.Option("default", "--name", "-n", help="Key name"),
    scopes: str = typer.Option(None, "--scopes", "-s", help="Comma-separated scopes"),
):
    """Generate an API key for a user."""
    from fastsmtp.db.models import APIKey, User
    from fastsmtp.db.session import async_session

    async def generate():
        async with async_session() as session:
            from sqlalchemy import select

            stmt = select(User).where(User.username == username)
            result = await session.execute(stmt)
            user = result.scalar_one_or_none()

            if not user:
                console.print(f"[red]User '{username}' not found[/red]")
                raise typer.Exit(1)

            full_key, key_prefix, key_hash, key_salt = generate_api_key()
            scope_list = scopes.split(",") if scopes else []

            api_key = APIKey(
                user_id=user.id,
                key_hash=key_hash,
                key_salt=key_salt,
                key_prefix=key_prefix,
                name=name,
                scopes=scope_list,
            )
            session.add(api_key)
            await session.commit()

            console.print(f"[green]Generated API key for '{username}':[/green]")
            console.print(f"[bold cyan]{full_key}[/bold cyan]")
            console.print("\n[yellow]Save this key - it cannot be retrieved later![/yellow]")

    run_async(generate())


# Domain commands


@domain_app.command("create")
def domain_create(
    domain_name: str = typer.Argument(..., help="Domain name"),
):
    """Create a new domain."""
    from fastsmtp.db.models import Domain
    from fastsmtp.db.session import async_session

    async def create():
        async with async_session() as session:
            from sqlalchemy import select

            stmt = select(Domain).where(Domain.domain_name == domain_name)
            result = await session.execute(stmt)
            if result.scalar_one_or_none():
                console.print(f"[red]Domain '{domain_name}' already exists[/red]")
                raise typer.Exit(1)

            domain = Domain(domain_name=domain_name)
            session.add(domain)
            await session.commit()
            await session.refresh(domain)

            console.print(f"[green]Created domain '{domain_name}' (ID: {domain.id})[/green]")

    run_async(create())


@domain_app.command("list")
def domain_list():
    """List all domains."""
    from fastsmtp.db.models import Domain
    from fastsmtp.db.session import async_session

    async def list_domains():
        async with async_session() as session:
            from sqlalchemy import select

            stmt = select(Domain).order_by(Domain.domain_name)
            result = await session.execute(stmt)
            domains = result.scalars().all()

            table = Table(title="Domains")
            table.add_column("ID", style="dim")
            table.add_column("Domain", style="cyan")
            table.add_column("Enabled")
            table.add_column("DKIM")
            table.add_column("SPF")

            for domain in domains:
                table.add_row(
                    str(domain.id)[:8],
                    domain.domain_name,
                    "✓" if domain.is_enabled else "✗",
                    str(domain.verify_dkim) if domain.verify_dkim is not None else "default",
                    str(domain.verify_spf) if domain.verify_spf is not None else "default",
                )

            console.print(table)

    run_async(list_domains())


@domain_app.command("delete")
def domain_delete(
    domain_name: str = typer.Argument(..., help="Domain name to delete"),
    force: bool = typer.Option(False, "--force", "-f", help="Skip confirmation"),
):
    """Delete a domain."""
    from fastsmtp.db.models import Domain
    from fastsmtp.db.session import async_session

    async def delete():
        async with async_session() as session:
            from sqlalchemy import select

            stmt = select(Domain).where(Domain.domain_name == domain_name)
            result = await session.execute(stmt)
            domain = result.scalar_one_or_none()

            if not domain:
                console.print(f"[red]Domain '{domain_name}' not found[/red]")
                raise typer.Exit(1)

            if not force:
                confirm = typer.confirm(f"Delete domain '{domain_name}'?")
                if not confirm:
                    raise typer.Abort()

            await session.delete(domain)
            await session.commit()
            console.print(f"[green]Deleted domain '{domain_name}'[/green]")

    run_async(delete())


@domain_app.command("add-member")
def domain_add_member(
    domain_name: str = typer.Argument(..., help="Domain name"),
    username: str = typer.Argument(..., help="Username to add"),
    role: str = typer.Option("member", "--role", "-r", help="Role: owner, admin, member"),
):
    """Add a member to a domain."""
    from fastsmtp.db.models import Domain, DomainMember, User
    from fastsmtp.db.session import async_session

    if role not in ("owner", "admin", "member"):
        console.print(f"[red]Invalid role '{role}'. Use: owner, admin, member[/red]")
        raise typer.Exit(1)

    async def add():
        async with async_session() as session:
            from sqlalchemy import select

            # Get domain
            domain_stmt = select(Domain).where(Domain.domain_name == domain_name)
            domain_result = await session.execute(domain_stmt)
            domain = domain_result.scalar_one_or_none()
            if not domain:
                console.print(f"[red]Domain '{domain_name}' not found[/red]")
                raise typer.Exit(1)

            # Get user
            user_stmt = select(User).where(User.username == username)
            user_result = await session.execute(user_stmt)
            user = user_result.scalar_one_or_none()
            if not user:
                console.print(f"[red]User '{username}' not found[/red]")
                raise typer.Exit(1)

            # Check existing membership
            member_stmt = select(DomainMember).where(
                DomainMember.domain_id == domain.id,
                DomainMember.user_id == user.id,
            )
            member_result = await session.execute(member_stmt)
            if member_result.scalar_one_or_none():
                console.print(
                    f"[red]User '{username}' is already a member of '{domain_name}'[/red]"
                )
                raise typer.Exit(1)

            member = DomainMember(domain_id=domain.id, user_id=user.id, role=role)
            session.add(member)
            await session.commit()

            console.print(
                f"[green]Added '{username}' to '{domain_name}' as {role}[/green]"
            )

    run_async(add())


@domain_app.command("remove-member")
def domain_remove_member(
    domain_name: str = typer.Argument(..., help="Domain name"),
    username: str = typer.Argument(..., help="Username to remove"),
):
    """Remove a member from a domain."""
    from fastsmtp.db.models import Domain, DomainMember, User
    from fastsmtp.db.session import async_session

    async def remove():
        async with async_session() as session:
            from sqlalchemy import select

            # Get domain
            domain_stmt = select(Domain).where(Domain.domain_name == domain_name)
            domain_result = await session.execute(domain_stmt)
            domain = domain_result.scalar_one_or_none()
            if not domain:
                console.print(f"[red]Domain '{domain_name}' not found[/red]")
                raise typer.Exit(1)

            # Get user
            user_stmt = select(User).where(User.username == username)
            user_result = await session.execute(user_stmt)
            user = user_result.scalar_one_or_none()
            if not user:
                console.print(f"[red]User '{username}' not found[/red]")
                raise typer.Exit(1)

            # Get membership
            member_stmt = select(DomainMember).where(
                DomainMember.domain_id == domain.id,
                DomainMember.user_id == user.id,
            )
            member_result = await session.execute(member_stmt)
            member = member_result.scalar_one_or_none()
            if not member:
                console.print(
                    f"[red]User '{username}' is not a member of '{domain_name}'[/red]"
                )
                raise typer.Exit(1)

            await session.delete(member)
            await session.commit()

            console.print(f"[green]Removed '{username}' from '{domain_name}'[/green]")

    run_async(remove())


@app.command()
def cleanup(
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be deleted without actually deleting"
    ),
    older_than: str | None = typer.Option(
        None, "--older-than", help="Override retention period (e.g., '30d', '6h')"
    ),
):
    """Clean up old delivery log records."""
    from fastsmtp.cleanup.service import DeliveryLogCleanupService
    from fastsmtp.db.session import async_session

    settings = get_settings()

    # Parse older_than if provided
    retention_days: int | None = None
    if older_than:
        retention_days = _parse_duration_to_days(older_than)
        if retention_days is None:
            console.print(f"[red]Invalid duration format: {older_than}[/red]")
            console.print("Use format like '30d' (days) or '6h' (hours)")
            raise typer.Exit(1)

    async def run_cleanup():
        async with async_session() as session:
            service = DeliveryLogCleanupService(settings, session)
            result = await service.cleanup(dry_run=dry_run, retention_days=retention_days)
            return result

    result = run_async(run_cleanup())

    cutoff_str = result.cutoff_date.strftime("%Y-%m-%d %H:%M:%S UTC")

    if dry_run:
        console.print(
            f"[yellow]Would delete {result.deleted_count} delivery log records "
            f"older than {cutoff_str}[/yellow]"
        )
    else:
        console.print(
            f"[green]Deleted {result.deleted_count} delivery log records "
            f"older than {cutoff_str}[/green]"
        )


def _parse_duration_to_days(duration: str) -> int | None:
    """Parse a duration string like '30d' or '6h' to days.

    Returns None if the format is invalid.
    """
    import re

    match = re.match(r"^(\d+)([dhm])$", duration.lower())
    if not match:
        return None

    value = int(match.group(1))
    unit = match.group(2)

    if unit == "d":
        return value
    elif unit == "h":
        # Convert hours to days (minimum 1 day if hours specified)
        return max(1, value // 24) if value >= 24 else 1
    elif unit == "m":
        # Minutes - minimum 1 day
        return 1

    return None


if __name__ == "__main__":
    app()
