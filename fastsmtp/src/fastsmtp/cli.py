"""FastSMTP server CLI.

Deletes are soft: ``user|domain delete`` tombstones the row, ``restore`` clears
the tombstone, and ``delete --purge`` runs the old hard delete on a row that is
already tombstoned. Every by-name lookup resolves the *live* row, so a
tombstone that shares the name never gets in the way (and never raises
``MultipleResultsFound``); the tombstone-addressed commands (``restore``,
``--purge``) refuse ambiguity and take ``--id``. The one lookup that reaches a
tombstone by name is ``remove-member``: taking a membership away is an
un-grant, so a deleted user's edge stays detachable. Every tombstone write and
every purge goes through ``fastsmtp.db.soft_delete``; nothing here stamps or
hard-deletes a soft-deletable row itself.

Imports stay lazy: ``version`` and ``db upgrade`` must not load the API package
(every router, FastAPI, the SMTP server, S3), so each command imports what it
needs inside its body.
"""

import asyncio
import logging
import sys
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from alembic import command as alembic_command
from alembic.util.exc import CommandError
from rich.console import Console
from rich.table import Table
from sqlalchemy import CursorResult, select
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from fastsmtp import __version__
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.integrity import is_unique_violation, live_value_taken
from fastsmtp.db.migrations import SchemaRevisionError, alembic_config
from fastsmtp.db.models import Domain, SoftDeleteMixin, User

app = typer.Typer(
    name="fastsmtp",
    help="FastSMTP - SMTP-to-Webhook Relay Server",
    no_args_is_help=True,
    # Typer renders frame locals in its pretty traceback by default, which put
    # the database password on the operator's terminal whenever settings failed
    # to validate (issue #140). Any secret that a frame happens to hold leaks
    # the same way, so this stays off however convenient it looks for debugging;
    # reach for a debugger instead.
    pretty_exceptions_show_locals=False,
)

console = Console()

# Subcommands
db_app = typer.Typer(help="Database management commands")
user_app = typer.Typer(help="User management commands")
domain_app = typer.Typer(help="Domain management commands")

app.add_typer(db_app, name="db")
app.add_typer(user_app, name="user")
app.add_typer(domain_app, name="domain")

TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# Options shared by the user and domain commands, so the flags read the same
# everywhere. Declared as ``force: Force = False`` -- the default goes on the
# parameter, not inside ``Annotated``.
Force = Annotated[bool, typer.Option("--force", "-f", help="Skip confirmation")]
IncludeDeleted = Annotated[
    bool, typer.Option("--include-deleted", help="Also list deleted (restorable) entries")
]
Purge = Annotated[
    bool,
    typer.Option(
        "--purge",
        help="Permanently delete an entry that is already deleted. Cannot be undone.",
    ),
]
TombstoneId = Annotated[
    uuid.UUID | None,
    typer.Option("--id", help="Pick one entry when several deleted entries share the name"),
]
DryRun = Annotated[
    bool, typer.Option("--dry-run", help="Show what would be deleted without actually deleting")
]
OlderThan = Annotated[
    str | None,
    typer.Option("--older-than", help="Override retention period in days (e.g., '30d')"),
]


def run_async(coro):
    """Run an async function synchronously."""
    return asyncio.run(coro)


def _cleanup_worker_started_line(settings: Settings) -> str:
    """Console line for ``serve``: the worker runs when either retention job is on."""
    interval = settings.delivery_log_cleanup_interval_hours
    logs = (
        f"{settings.delivery_log_retention_days}d"
        if settings.delivery_log_cleanup_enabled
        else "off"
    )
    days = settings.soft_delete_retention_days
    tombstones = f"{days}d" if days is not None else "never"
    return (
        f"Cleanup worker started (interval: {interval}h, delivery-log retention: {logs}, "
        f"soft-delete retention: {tombstones})"
    )


async def _run_startup_guards(settings: Settings) -> None:
    """Refuse to start against a database this process cannot serve.

    The checks themselves are ``db.startup``, shared with the API lifespan;
    this is the CLI's half of the arrangement, which is how a failure is
    reported. A stale schema or an unreadable encrypted column is an operator
    error, so it is a console message and exit 1 rather than a traceback.

    Called from ``serve`` because the lifespan runs only when uvicorn does:
    ``--worker-only`` and ``--smtp-only`` reached the database with no check at
    all (issue #138), and the worker is the component that most needs the
    encrypted headers, since it is what sends them.
    """
    from fastsmtp.db.encryption_guard import EncryptionKeyMissingError
    from fastsmtp.db.startup import verify_database_is_serviceable

    try:
        await verify_database_is_serviceable(settings)
    except (SchemaRevisionError, EncryptionKeyMissingError) as exc:
        raise _fail(str(exc)) from exc


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
                shutdown_tasks.append(smtp_server.stop())
                console.print("[dim]Stopping SMTP server...[/dim]")

            # Wait for async shutdowns with timeout
            if shutdown_tasks:
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*shutdown_tasks, return_exceptions=True),
                        timeout=shutdown_timeout,
                    )
                except TimeoutError:
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

        # Every mode of serve, before any component starts.
        await _run_startup_guards(settings)

        tasks = []

        if not api_only and not worker_only:
            # Start SMTP server (async - runs on same event loop)
            smtp_server = SMTPServer(settings)
            await smtp_server.start()
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
                # uvicorn's proxy_headers default rewrites the peer address from
                # the leftmost X-Forwarded-For entry, which the client controls.
                # FastSMTP resolves that header itself, gated on
                # metrics_trusted_proxies, so the raw peer must reach the app
                # intact - otherwise the metrics allowlist checks a forged value.
                proxy_headers=False,
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

            # Start cleanup worker (runs when either retention job is enabled)
            cleanup_worker = CleanupWorker(settings)
            cleanup_worker.start()
            if cleanup_worker.enabled:
                console.print(f"[green]{_cleanup_worker_started_line(settings)}[/green]")

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

    # On the class, not the instance: pydantic 2.11 deprecates the instance
    # attribute and V3 removes it. Under this repo's warnings-as-errors the
    # instance form does not warn, it raises - so `show-config` exited 1 with an
    # empty table. It looked healthy only because the one test that ran it did
    # so in a child process, where the warning is not fatal.
    for field_name in type(settings).model_fields:
        value = getattr(settings, field_name)
        # Hide sensitive values
        if field_name == "database_url":
            # Masking the whole URL would hide the host and database name too,
            # and "which database am I pointed at" is most of why anyone runs
            # this command. SQLAlchemy's own renderer redacts just the
            # password, so there is no hand-written parser here to get it
            # wrong. See issue #140.
            value = make_url(settings.database_dsn).render_as_string(hide_password=True)
        elif "key" in field_name.lower() or "secret" in field_name.lower():
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
    _run_alembic(alembic_command.upgrade, revision)


@db_app.command("downgrade")
def db_downgrade(
    revision: str = typer.Argument(..., help="Revision to downgrade to"),
):
    """Downgrade database to a revision."""
    _run_alembic(alembic_command.downgrade, revision)


@db_app.command("revision")
def db_revision(
    message: str = typer.Option(..., "-m", "--message", help="Revision message"),
    autogenerate: bool = typer.Option(True, "--autogenerate/--no-autogenerate"),
):
    """Create a new database revision."""
    _run_alembic(alembic_command.revision, message=message, autogenerate=autogenerate)


@db_app.command("current")
def db_current():
    """Show current database revision."""
    _run_alembic(alembic_command.current)


@db_app.command("history")
def db_history():
    """Show revision history."""
    _run_alembic(alembic_command.history)


def _run_alembic(command: Callable[..., object], *args: object, **kwargs: object) -> None:
    """Run one Alembic command in this process.

    These used to be spawned as ``python -m alembic -c <ini>`` from the package
    directory, because that is the only way the Alembic CLI can find its
    config. The migrations ship inside the package now and the config is built
    in code, so there is nothing left for a child process to solve - and two
    problems it used to create go away with it: the ini had to be located by
    walking up from ``__file__``, and the child resolved settings relative to
    its own working directory rather than the operator's (issue #114). Running
    here, ``env.py`` builds its settings in the process the operator started,
    so ``db`` and ``serve`` read one ``.env`` by construction.

    A bad revision id is a user error, not a crash, so Alembic's own
    ``CommandError`` is reported and exits 1. Anything else - a database that
    refuses the connection, a broken migration - keeps its traceback.
    """
    _configure_migration_logging()
    try:
        command(alembic_config(), *args, **kwargs)
    except CommandError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc


def _configure_migration_logging() -> None:
    """Attach the handler alembic.ini used to configure for the child process.

    Alembic announces each revision it applies through its own logger at INFO.
    With nothing listening that output is dropped and ``db upgrade head``
    applies the chain in silence, which an operator cannot tell from a no-op.
    Everything else keeps the default WARNING and reaches stderr through
    logging's last-resort handler.

    The ``NullHandler`` is the catch: ``alembic.util.messaging`` attaches one
    to this logger at import time, the library convention for staying quiet by
    default. It is already there before this runs, so "does the logger have
    handlers" is the wrong question - only a handler that actually emits
    counts, or this returns early and configures nothing.
    """
    logger = logging.getLogger("alembic")
    if any(not isinstance(handler, logging.NullHandler) for handler in logger.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)-5.5s [%(name)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# Soft-delete helpers shared by the user and domain commands


def _fail(message: str) -> typer.Exit:
    """Print ``message`` in red and return the exit to raise."""
    console.print(f"[red]{message}[/red]")
    return typer.Exit(1)


def _confirm(force: bool, prompt: str) -> None:
    """Ask before a destructive step unless ``--force`` was given."""
    if not force and not typer.confirm(prompt):
        raise typer.Abort()


def _format_timestamp(value: datetime | None) -> str:
    """A tombstone stamp or a retention cutoff, both in explicit UTC; empty for ``None``."""
    return f"{value.strftime(TIMESTAMP_FORMAT)} UTC" if value is not None else ""


def _yes_no(value: bool) -> str:
    """Render a flag cell as the same words fsmtp uses, so the cell text is plain ASCII.

    Only the cell is ours: Rich still draws the table frame with box characters
    on a UTF-8 console and falls back to ASCII on any other encoding.
    """
    return "Yes" if value else "No"


def _require_purge_for_id(purge: bool, id_option: uuid.UUID | None) -> None:
    """``--id`` names a tombstone; a plain delete addresses the live row and has no use for it.

    Ignoring the flag would soft-delete the live namesake the operator never
    meant to touch, and revoke its API keys for good.
    """
    if id_option is not None and not purge:
        raise _fail("--id only applies with --purge; delete addresses the live entry")


async def _live_user(session: AsyncSession, username: str) -> User | None:
    """The live user of that name, if any. Tombstones never match (S20)."""
    stmt = select(User).where(User.username == username, User.live())
    return (await session.execute(stmt)).scalar_one_or_none()


async def _live_domain(session: AsyncSession, domain_name: str) -> Domain | None:
    """The live domain of that name, if any. Tombstones never match (S20)."""
    stmt = select(Domain).where(Domain.domain_name == domain_name, Domain.live())
    return (await session.execute(stmt)).scalar_one_or_none()


async def _require_live_user(session: AsyncSession, username: str) -> User:
    user = await _live_user(session, username)
    if user is None:
        raise _fail(f"User '{username}' not found")
    return user


async def _require_live_domain(session: AsyncSession, domain_name: str) -> Domain:
    domain = await _live_domain(session, domain_name)
    if domain is None:
        raise _fail(f"Domain '{domain_name}' not found")
    return domain


async def _tombstones[Named: (User, Domain)](
    session: AsyncSession,
    model: type[Named],
    column: InstrumentedAttribute[str],
    name: str,
) -> Sequence[Named]:
    """Deleted rows whose ``column`` equals ``name``, newest tombstone first."""
    stmt = select(model).where(column == name, ~model.live()).order_by(model.deleted_at.desc())
    return (await session.execute(stmt)).scalars().all()


def _resolve_tombstone[Named: (User, Domain)](
    rows: Sequence[Named], id_option: uuid.UUID | None, kind: str, name: str
) -> Named:
    """Pick the tombstone a restore/purge addresses; refuse to guess between several."""
    if not rows:
        raise _fail(f"No deleted {kind} '{name}'")
    if id_option is not None:
        for row in rows:
            if row.id == id_option:
                return row
        raise _fail(f"No deleted {kind} '{name}' with ID {id_option}")
    if len(rows) > 1:
        console.print(f"[red]{len(rows)} deleted {kind}s are named '{name}'; pass --id:[/red]")
        for row in rows:
            console.print(f"  {row.id}  deleted {_format_timestamp(row.deleted_at)}")
        raise typer.Exit(1)
    return rows[0]


async def _tombstone[Named: (User, Domain)](
    session: AsyncSession,
    model: type[Named],
    column: InstrumentedAttribute[str],
    name: str,
    id_option: uuid.UUID | None,
    kind: str,
    *,
    live: Named | None = None,
) -> Named:
    """The tombstone a restore or purge addresses.

    ``--purge`` passes the live namesake, if any: a name that is only live is
    refused with a pointer to delete it first, so purge is never a one-shot
    delete of the wrong row.
    """
    rows = await _tombstones(session, model, column, name)
    if not rows and live is not None:
        raise _fail(f"{kind.capitalize()} '{name}' is not deleted; delete it first, then --purge")
    return _resolve_tombstone(rows, id_option, kind, name)


async def _commit_or_conflict(session: AsyncSession, message: str) -> None:
    """Commit a create or restore; a lost race on the name reports ``message``.

    The pre-check is check-then-commit, so a name taken between the two (a
    concurrent create, or a restore of the tombstoned namesake) hits the
    partial unique index (migration 008) here instead.
    """
    try:
        await session.commit()
    except IntegrityError as exc:
        if not is_unique_violation(exc):
            raise
        raise _fail(message) from exc


async def _member_user_ids(session: AsyncSession, username: str) -> list[uuid.UUID]:
    """The users ``remove-member`` may detach: the live one, else the tombstones.

    Unlike ``add-member`` this is an un-grant, so it reaches a deleted user the
    way the REST API does. Without a live namesake every deleted one is
    detached: none of them can hold the membership until restored.
    """
    user = await _live_user(session, username)
    if user is not None:
        return [user.id]
    rows = await _tombstones(session, User, User.username, username)
    if not rows:
        raise _fail(f"User '{username}' not found")
    return [row.id for row in rows]


def _add_deleted_column(table: Table, include_deleted: bool) -> None:
    if include_deleted:
        table.add_column("Deleted", style="red")


def _add_row(table: Table, row: SoftDeleteMixin, *cells: str, include_deleted: bool) -> None:
    """Add a list row; with ``--include-deleted`` the tombstone stamp joins it, dimmed."""
    if include_deleted:
        cells = (*cells, _format_timestamp(row.deleted_at))
    table.add_row(*cells, style="dim" if row.is_deleted else None)


# User commands


@user_app.command("create")
def user_create(
    username: str = typer.Argument(..., help="Username"),
    email: str = typer.Option(None, "--email", "-e", help="Email address"),
    superuser: bool = typer.Option(False, "--superuser", help="Create as superuser"),
):
    """Create a new user."""
    from fastsmtp.db.session import async_session

    async def create():
        async with async_session() as session:
            conflict = f"User '{username}' already exists"
            if await live_value_taken(session, User, User.username, username):
                raise _fail(conflict)

            user = User(username=username, email=email, is_superuser=superuser)
            session.add(user)
            await _commit_or_conflict(session, conflict)
            await session.refresh(user)

            console.print(f"[green]Created user '{username}' (ID: {user.id})[/green]")
            if superuser:
                console.print("[yellow]User is a superuser[/yellow]")

    run_async(create())


@user_app.command("list")
def user_list(include_deleted: IncludeDeleted = False):
    """List all users."""
    from fastsmtp.db.session import async_session
    from fastsmtp.db.soft_delete import visible

    async def list_users():
        async with async_session() as session:
            stmt = select(User).where(visible(User, include_deleted)).order_by(User.username)
            result = await session.execute(stmt)
            users = result.scalars().all()

            table = Table(title="Users")
            table.add_column("ID", style="dim")
            table.add_column("Username", style="cyan")
            table.add_column("Email")
            table.add_column("Active")
            table.add_column("Superuser")
            _add_deleted_column(table, include_deleted)

            for user in users:
                _add_row(
                    table,
                    user,
                    str(user.id)[:8],
                    user.username,
                    user.email or "",
                    _yes_no(user.is_active),
                    _yes_no(user.is_superuser),
                    include_deleted=include_deleted,
                )

            console.print(table)

    run_async(list_users())


@user_app.command("delete")
def user_delete(
    username: str = typer.Argument(..., help="Username to delete"),
    force: Force = False,
    purge: Purge = False,
    id_option: TombstoneId = None,
):
    """Delete a user (restorable with 'user restore'), or --purge one already deleted.

    Deleting revokes the user's API keys for good; memberships return on restore.
    --purge permanently removes a deleted user with their keys and memberships.
    """
    from fastsmtp.db import soft_delete
    from fastsmtp.db.session import async_session

    _require_purge_for_id(purge, id_option)

    async def delete():
        async with async_session() as session:
            if purge:
                user = await _tombstone(
                    session,
                    User,
                    User.username,
                    username,
                    id_option,
                    "user",
                    live=await _live_user(session, username),
                )
                _confirm(
                    force,
                    f"Permanently delete user '{username}' "
                    f"(deleted {_format_timestamp(user.deleted_at)}) and all their API keys "
                    "and memberships? This cannot be undone.",
                )
                await soft_delete.purge_user(session, user)
                await session.commit()
                console.print(f"[green]Purged user '{username}'[/green]")
                return

            user = await _require_live_user(session, username)
            _confirm(
                force,
                f"Delete user '{username}'? Their API keys are revoked for good; the user is "
                f"restorable with: fastsmtp user restore {username}",
            )
            revoked = await soft_delete.soft_delete_user(session, user)
            await session.commit()
            console.print(
                f"[green]Deleted user '{username}' ({revoked} API key(s) revoked; "
                f"restore with: fastsmtp user restore {username})[/green]"
            )

    run_async(delete())


@user_app.command("restore")
def user_restore(
    username: str = typer.Argument(..., help="Username to restore"),
    id_option: TombstoneId = None,
):
    """Restore a deleted user. API keys revoked at deletion stay revoked."""
    from fastsmtp.db import soft_delete
    from fastsmtp.db.session import async_session

    conflict = f"User '{username}' already exists; rename or purge it first"

    async def restore():
        async with async_session() as session:
            user = await _tombstone(session, User, User.username, username, id_option, "user")
            if await live_value_taken(session, User, User.username, username):
                raise _fail(conflict)

            await soft_delete.restore_user(session, user)
            await _commit_or_conflict(session, conflict)

            console.print(f"[green]Restored user '{username}' (ID: {user.id})[/green]")
            console.print(
                "[yellow]API keys revoked at deletion are not restored; generate new ones "
                f"with: fastsmtp user generate-key {username}[/yellow]"
            )

    run_async(restore())


@user_app.command("set-superuser")
def user_set_superuser(
    username: str = typer.Argument(..., help="Username"),
    enable: bool = typer.Option(None, "--enable/--disable", help="Enable or disable superuser"),
):
    """Set or unset superuser status."""
    from fastsmtp.db.session import async_session

    if enable is None:
        raise _fail("Please specify --enable or --disable")

    async def update():
        async with async_session() as session:
            user = await _require_live_user(session, username)

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
    # fastsmtp.auth's package __init__ pulls in the FastAPI dependencies, so
    # the key helper is imported by the one command that mints keys.
    from fastsmtp.auth.keys import generate_api_key
    from fastsmtp.db.models import APIKey
    from fastsmtp.db.session import async_session

    async def generate():
        async with async_session() as session:
            # A deleted user is simply not found: no key may be minted for a tombstone.
            user = await _require_live_user(session, username)

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
    from fastsmtp.db.session import async_session

    async def create():
        async with async_session() as session:
            conflict = f"Domain '{domain_name}' already exists"
            if await live_value_taken(session, Domain, Domain.domain_name, domain_name):
                raise _fail(conflict)

            domain = Domain(domain_name=domain_name)
            session.add(domain)
            await _commit_or_conflict(session, conflict)
            await session.refresh(domain)

            console.print(f"[green]Created domain '{domain_name}' (ID: {domain.id})[/green]")

    run_async(create())


class TriState(str, Enum):
    """A per-domain override of a server-wide boolean setting.

    ``inherit`` clears the override so the domain follows the server default;
    leaving the option off entirely means "don't touch this setting". Spelled
    exactly as ``fsmtp domain update`` spells it: the two CLIs write the same
    nullable columns and an operator should not have to learn it twice.
    """

    true = "true"
    false = "false"
    inherit = "inherit"


def _tri_state_value(option: TriState) -> bool | None:
    """The column value a tri-state option asks for; ``inherit`` is SQL NULL."""
    if option is TriState.true:
        return True
    if option is TriState.false:
        return False
    return None


def _flag_text(value: bool | None) -> str:
    """Render a written flag back in the words the options use."""
    return "inherit" if value is None else str(value).lower()


# Option names and help mirror fsmtp's, minus its "superuser only" note: that
# describes who the API lets set these, and a local CLI has no caller to check.
# The command's own help says what that means here.
VerifyDkim = Annotated[
    TriState | None,
    typer.Option("--verify-dkim", help="Verify DKIM signatures (true/false/inherit)"),
]
VerifySpf = Annotated[
    TriState | None,
    typer.Option("--verify-spf", help="Verify SPF records (true/false/inherit)"),
]
RejectDkimFail = Annotated[
    TriState | None,
    typer.Option("--reject-dkim-fail", help="Reject on DKIM failure (true/false/inherit)"),
]
RejectSpfFail = Annotated[
    TriState | None,
    typer.Option("--reject-spf-fail", help="Reject on SPF failure (true/false/inherit)"),
]
PreserveRawMessage = Annotated[
    TriState | None,
    typer.Option(
        "--preserve-raw-message",
        help="Preserve the raw MIME message in S3 (true/false/inherit)",
    ),
]
Enable = Annotated[
    bool | None,
    typer.Option("--enable/--disable", help="Enable or disable the domain"),
]


@domain_app.command("update")
def domain_update(
    domain_name: str = typer.Argument(..., help="Domain name"),
    enable: Enable = None,
    verify_dkim: VerifyDkim = None,
    verify_spf: VerifySpf = None,
    reject_dkim_fail: RejectDkimFail = None,
    reject_spf_fail: RejectSpfFail = None,
    preserve_raw_message: PreserveRawMessage = None,
):
    """Change a domain's settings. At least one option is required.

    The five override options take true, false or inherit: inherit clears the
    override so the domain follows the server-wide setting, which is a
    different state from false. An option not given leaves that setting alone.

    Over the API the four authentication options are superuser only, since a
    domain admin could otherwise opt their domain out of the operator's reject
    policy. This CLI runs on the server with no caller identity and sets them
    for any domain.
    """
    from fastsmtp.db.session import async_session

    changes: dict[str, bool | None] = {}
    if enable is not None:
        changes["is_enabled"] = enable
    for field, option in (
        ("verify_dkim", verify_dkim),
        ("verify_spf", verify_spf),
        ("reject_dkim_fail", reject_dkim_fail),
        ("reject_spf_fail", reject_spf_fail),
        ("preserve_raw_message", preserve_raw_message),
    ):
        if option is not None:
            changes[field] = _tri_state_value(option)

    if not changes:
        raise _fail("At least one option must be provided")

    # The flag is stored here but acted on by the SMTP server, and this command
    # never reaches the API check that would refuse it, so it asks the same
    # question of the same settings.
    if changes.get("preserve_raw_message") is True:
        unavailable = get_settings().raw_preservation_unavailable()
        if unavailable:
            raise _fail(unavailable)

    async def update():
        async with async_session() as session:
            domain = await _require_live_domain(session, domain_name)

            for field, value in changes.items():
                setattr(domain, field, value)
            await session.commit()

            summary = ", ".join(f"{field}={_flag_text(value)}" for field, value in changes.items())
            console.print(f"[green]Updated domain '{domain_name}' ({summary})[/green]")

    run_async(update())


@domain_app.command("list")
def domain_list(include_deleted: IncludeDeleted = False):
    """List all domains."""
    from fastsmtp.db.session import async_session
    from fastsmtp.db.soft_delete import visible

    async def list_domains():
        async with async_session() as session:
            stmt = (
                select(Domain).where(visible(Domain, include_deleted)).order_by(Domain.domain_name)
            )
            result = await session.execute(stmt)
            domains = result.scalars().all()

            table = Table(title="Domains")
            table.add_column("ID", style="dim")
            table.add_column("Domain", style="cyan")
            table.add_column("Enabled")
            table.add_column("DKIM")
            table.add_column("SPF")
            _add_deleted_column(table, include_deleted)

            for domain in domains:
                _add_row(
                    table,
                    domain,
                    str(domain.id)[:8],
                    domain.domain_name,
                    _yes_no(domain.is_enabled),
                    str(domain.verify_dkim) if domain.verify_dkim is not None else "default",
                    str(domain.verify_spf) if domain.verify_spf is not None else "default",
                    include_deleted=include_deleted,
                )

            console.print(table)

    run_async(list_domains())


@domain_app.command("delete")
def domain_delete(
    domain_name: str = typer.Argument(..., help="Domain name to delete"),
    force: Force = False,
    purge: Purge = False,
    id_option: TombstoneId = None,
):
    """Delete a domain (restorable with 'domain restore'), or --purge one already deleted.

    Deleting also deletes the domain's recipients and cancels their queued deliveries.
    Rulesets and members are kept and return on restore.
    --purge permanently removes a deleted domain with its recipients, rulesets and members.
    Delivery history survives a purge with its domain and recipient links cleared.
    """
    from fastsmtp.db import soft_delete
    from fastsmtp.db.session import async_session

    _require_purge_for_id(purge, id_option)

    async def delete():
        async with async_session() as session:
            if purge:
                domain = await _tombstone(
                    session,
                    Domain,
                    Domain.domain_name,
                    domain_name,
                    id_option,
                    "domain",
                    live=await _live_domain(session, domain_name),
                )
                _confirm(
                    force,
                    f"Permanently delete domain '{domain_name}' "
                    f"(deleted {_format_timestamp(domain.deleted_at)}) and all its recipients, "
                    "rulesets and members? This cannot be undone.",
                )
                await soft_delete.purge_domain(session, domain)
                await session.commit()
                console.print(f"[green]Purged domain '{domain_name}'[/green]")
                return

            domain = await _require_live_domain(session, domain_name)
            _confirm(
                force,
                f"Delete domain '{domain_name}'? "
                f"(restorable with: fastsmtp domain restore {domain_name})",
            )
            recipients, cancelled = await soft_delete.soft_delete_domain(session, domain)
            await session.commit()
            console.print(
                f"[green]Deleted domain '{domain_name}' ({recipients} recipient(s) deleted, "
                f"{cancelled} delivery(ies) cancelled; "
                f"restore with: fastsmtp domain restore {domain_name})[/green]"
            )

    run_async(delete())


@domain_app.command("restore")
def domain_restore(
    domain_name: str = typer.Argument(..., help="Domain name to restore"),
    id_option: TombstoneId = None,
):
    """Restore a deleted domain and the recipients deleted with it."""
    from fastsmtp.db import soft_delete
    from fastsmtp.db.session import async_session

    conflict = f"Domain '{domain_name}' already exists; rename or purge it first"

    async def restore():
        async with async_session() as session:
            domain = await _tombstone(
                session, Domain, Domain.domain_name, domain_name, id_option, "domain"
            )
            if await live_value_taken(session, Domain, Domain.domain_name, domain_name):
                raise _fail(conflict)

            recipients = await soft_delete.restore_domain(session, domain)
            await _commit_or_conflict(session, conflict)

            console.print(f"[green]Restored domain '{domain_name}' (ID: {domain.id})[/green]")
            console.print(f"[green]{recipients} recipient(s) restored[/green]")

    run_async(restore())


@domain_app.command("add-member")
def domain_add_member(
    domain_name: str = typer.Argument(..., help="Domain name"),
    username: str = typer.Argument(..., help="Username to add"),
    role: str = typer.Option("member", "--role", "-r", help="Role: owner, admin, member"),
):
    """Add a member to a domain."""
    from fastsmtp.db.models import DomainMember
    from fastsmtp.db.session import async_session

    if role not in ("owner", "admin", "member"):
        raise _fail(f"Invalid role '{role}'. Use: owner, admin, member")

    async def add():
        async with async_session() as session:
            domain = await _require_live_domain(session, domain_name)
            # A deleted user is not found: no membership is granted to a tombstone.
            user = await _require_live_user(session, username)

            # Check existing membership
            member_stmt = select(DomainMember).where(
                DomainMember.domain_id == domain.id,
                DomainMember.user_id == user.id,
            )
            member_result = await session.execute(member_stmt)
            if member_result.scalar_one_or_none():
                raise _fail(f"User '{username}' is already a member of '{domain_name}'")

            member = DomainMember(domain_id=domain.id, user_id=user.id, role=role)
            session.add(member)
            await session.commit()

            console.print(f"[green]Added '{username}' to '{domain_name}' as {role}[/green]")

    run_async(add())


@domain_app.command("remove-member")
def domain_remove_member(
    domain_name: str = typer.Argument(..., help="Domain name"),
    username: str = typer.Argument(..., help="Username to remove"),
):
    """Remove a member from a domain."""
    from sqlalchemy import delete

    from fastsmtp.db.models import DomainMember
    from fastsmtp.db.session import async_session

    async def remove():
        async with async_session() as session:
            domain = await _require_live_domain(session, domain_name)
            user_ids = await _member_user_ids(session, username)

            # Membership is an edge with no tombstone of its own: removing it is
            # a hard delete, as before.
            member_stmt = delete(DomainMember).where(
                DomainMember.domain_id == domain.id,
                DomainMember.user_id.in_(user_ids),
            )
            result = await session.execute(member_stmt)
            assert isinstance(result, CursorResult)  # execute() is typed as Result[Any]
            if result.rowcount == 0:
                raise _fail(f"User '{username}' is not a member of '{domain_name}'")
            await session.commit()

            console.print(f"[green]Removed '{username}' from '{domain_name}'[/green]")

    run_async(remove())


# Maintenance commands


def _retention_override(older_than: str | None) -> int | None:
    """Days from ``--older-than``; ``None`` when not given. Exits on a bad format."""
    if not older_than:
        return None
    retention_days = _parse_duration_to_days(older_than)
    if retention_days is None:
        console.print(f"[red]Invalid duration format: {older_than}[/red]")
        console.print("Use format like '30d' (days)")
        raise typer.Exit(1)
    return retention_days


@app.command()
def cleanup(dry_run: DryRun = False, older_than: OlderThan = None):
    """Clean up old delivery log records."""
    from fastsmtp.cleanup.service import DeliveryLogCleanupService
    from fastsmtp.db.session import async_session

    settings = get_settings()
    retention_days = _retention_override(older_than)

    async def run_cleanup():
        async with async_session() as session:
            service = DeliveryLogCleanupService(settings, session)
            result = await service.cleanup(dry_run=dry_run, retention_days=retention_days)
            return result

    result = run_async(run_cleanup())

    cutoff_str = _format_timestamp(result.cutoff_date)

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


@app.command("purge-deleted")
def purge_deleted(dry_run: DryRun = False, older_than: OlderThan = None):
    """Permanently remove users, API keys, domains and recipients deleted long enough ago.

    The retention period is FASTSMTP_SOFT_DELETE_RETENTION_DAYS unless --older-than is given.
    Delivery history survives a purge with its domain and recipient links cleared.
    """
    from fastsmtp.cleanup.purge import SoftDeletePurgeService
    from fastsmtp.db.session import async_session

    settings = get_settings()
    retention_days = _retention_override(older_than)
    # The service has no cutoff to compute without a window; that is decidable
    # here, before a session is opened, and it is the only input error left
    # (settings and --older-than both reject anything under a day).
    if retention_days is None and settings.soft_delete_retention_days is None:
        raise _fail(
            "No retention configured. Set FASTSMTP_SOFT_DELETE_RETENTION_DAYS or pass --older-than."
        )

    async def run_purge():
        async with async_session() as session:
            service = SoftDeletePurgeService(settings, session)
            return await service.purge(dry_run=dry_run, retention_days=retention_days)

    result = run_async(run_purge())

    verb, colour = ("Would purge", "yellow") if dry_run else ("Purged", "green")
    console.print(
        f"[{colour}]{verb} {result.total} soft-deleted rows older than "
        f"{_format_timestamp(result.cutoff_date)} ({result.breakdown})[/{colour}]"
    )


@app.command("encrypt-existing")
def encrypt_existing(
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show what would be written without writing anything"
    ),
    batch_size: int = typer.Option(
        500, "--batch-size", min=1, help="Recipients to convert per transaction"
    ),
):
    """Store every recipient's webhook headers encrypted under the current key.

    Two jobs, one pass. A row only takes the encrypted form when it is
    rewritten, so a recipient nobody edits keeps its headers in clear
    indefinitely; this converts them deliberately. And once a new key has been
    prepended to FASTSMTP_ENCRYPTION_KEYS, the same pass re-encrypts every row
    under it, which is what lets the superseded key be dropped.

    Deleted (restorable) recipients are converted too: their headers are still
    in the database, and a restore hands them back.
    """
    from sqlalchemy import JSON, type_coerce
    from sqlalchemy.orm.attributes import flag_modified

    from fastsmtp.crypto import DecryptionError, is_encrypted
    from fastsmtp.db.models import Recipient
    from fastsmtp.db.session import async_session
    from fastsmtp.encryption import get_cipher

    if get_cipher() is None:
        raise _fail(
            "No encryption key is configured, so there is nothing to encrypt with. "
            "Set FASTSMTP_ENCRYPTION_KEYS first."
        )

    async def convert() -> tuple[int, int, int]:
        """Walk every recipient in id order; returns (examined, in clear, already encrypted)."""
        examined = in_clear = encrypted = 0
        after: uuid.UUID | None = None

        async with async_session() as session:
            while True:
                # The column is selected twice on purpose. The entity load
                # decrypts it, which is what the rewrite needs; the type_coerce
                # copy comes back exactly as stored, and that is the only way
                # to tell a row that was never encrypted from one written under
                # an older key - the ORM sees plaintext either way.
                stmt = (
                    # The label keeps it a column of its own: an unlabelled
                    # copy renders as the same SQL as the entity's column and
                    # is deduplicated out of the result.
                    select(Recipient, type_coerce(Recipient.webhook_headers, JSON).label("stored"))
                    .order_by(Recipient.id)
                    .limit(batch_size)
                )
                if after is not None:
                    stmt = stmt.where(Recipient.id > after)

                try:
                    rows = (await session.execute(stmt)).all()
                except DecryptionError as exc:
                    raise _fail(
                        f"{exc}\nStopped after {examined} recipient(s); the ones already "
                        "converted are committed, so this can be run again once the "
                        "missing key is back in FASTSMTP_ENCRYPTION_KEYS."
                    ) from exc

                if not rows:
                    return examined, in_clear, encrypted

                for recipient, stored in rows:
                    examined += 1
                    after = recipient.id
                    if is_encrypted(stored):
                        encrypted += 1
                    else:
                        in_clear += 1
                    if not dry_run:
                        # The column type decrypts on load and encrypts on
                        # flush, so the value the ORM holds is the same
                        # plaintext before and after: assigning it back changes
                        # nothing and SQLAlchemy emits no UPDATE at all.
                        # Marking the attribute dirty is what makes the flush
                        # write - and therefore re-encrypt - the row.
                        flag_modified(recipient, "webhook_headers")

                if not dry_run:
                    # Per batch, so a large estate is not one long transaction.
                    await session.commit()
                # Nothing below refers to these rows again, and the identity map
                # would otherwise hold every recipient in the table by the end.
                session.expunge_all()

    examined, in_clear, encrypted = run_async(convert())

    if dry_run:
        console.print(
            f"[yellow]Would encrypt {in_clear} recipient(s) stored in clear and re-encrypt "
            f"{encrypted} under the current key ({examined} examined)[/yellow]"
        )
    else:
        console.print(
            f"[green]Encrypted {in_clear} recipient(s) stored in clear and re-encrypted "
            f"{encrypted} under the current key ({examined} examined)[/green]"
        )


def _parse_duration_to_days(duration: str) -> int | None:
    """Parse a duration string like '30d' to days.

    Only accepts days format to avoid misleading conversions.
    Returns None if the format is invalid.
    """
    import re

    match = re.match(r"^(\d+)d$", duration.lower())
    if not match:
        return None

    value = int(match.group(1))
    return value if value > 0 else None


if __name__ == "__main__":
    app()
