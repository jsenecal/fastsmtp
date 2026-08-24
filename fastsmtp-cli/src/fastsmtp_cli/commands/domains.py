"""Domain and member management commands.

``delete`` is a soft delete: the domain stops receiving mail, its recipients
are deleted with it and their queued deliveries are cancelled, but
``restore`` brings everything back (recipients deleted independently earlier
stay deleted). ``delete --purge`` removes an already-deleted domain for good,
together with its recipients, rulesets and members.
"""

from enum import Enum
from typing import Annotated, Any

import typer

from fastsmtp_cli.client import UNSET, APIError, FastSMTPClient
from fastsmtp_cli.commands.options import IncludeDeleted, Purge, confirm_delete
from fastsmtp_cli.output import (
    print_deleted,
    print_domain,
    print_domains_table,
    print_error,
    print_members_table,
    print_success,
)

app = typer.Typer(help="Domain management")


class TriState(str, Enum):
    """A per-domain override of a server-wide boolean setting.

    ``inherit`` clears the override so the domain follows the server default;
    leaving the option off entirely means "don't touch this setting".
    """

    true = "true"
    false = "false"
    inherit = "inherit"


def _tri_state_value(option: TriState | None) -> bool | None:
    """Map a tri-state option to the boolean (or null) the API expects."""
    if option is TriState.true:
        return True
    if option is TriState.false:
        return False
    return None


def _create_flag(option: TriState | None) -> bool | None:
    """Flag value for a create call: ``inherit`` and "unset" both mean omit."""
    if option is None or option is TriState.inherit:
        return None
    return _tri_state_value(option)


def _update_flag(option: TriState | None) -> Any:
    """Flag value for an update call, keeping "unset" distinct from ``inherit``."""
    if option is None:
        return UNSET
    return _tri_state_value(option)


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


@app.command("list")
def list_domains(
    include_deleted: IncludeDeleted = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List domains you have access to (deleted ones only where you are owner)."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            domains = client.list_domains(include_deleted=include_deleted)
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
    include_deleted: IncludeDeleted = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get domain details (a deleted domain is not found without --include-deleted)."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            domain = client.get_domain(domain_id, include_deleted=include_deleted)
            print_domain(domain)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("create")
def create_domain(
    domain_name: Annotated[str, typer.Argument(help="Domain name (e.g., example.com)")],
    verify_dkim: VerifyDkim = None,
    verify_spf: VerifySpf = None,
    reject_dkim_fail: RejectDkimFail = None,
    reject_spf_fail: RejectSpfFail = None,
    preserve_raw_message: PreserveRawMessage = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new domain."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            domain = client.create_domain(
                domain_name=domain_name,
                verify_dkim=_create_flag(verify_dkim),
                verify_spf=_create_flag(verify_spf),
                reject_dkim_fail=_create_flag(reject_dkim_fail),
                reject_spf_fail=_create_flag(reject_spf_fail),
                preserve_raw_message=_create_flag(preserve_raw_message),
            )
            print_success(f"Domain '{domain_name}' created")
            print_domain(domain)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("update")
def update_domain(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    enabled: Annotated[
        bool | None,
        typer.Option("--enabled/--disabled", help="Enable or disable domain"),
    ] = None,
    verify_dkim: VerifyDkim = None,
    verify_spf: VerifySpf = None,
    reject_dkim_fail: RejectDkimFail = None,
    reject_spf_fail: RejectSpfFail = None,
    preserve_raw_message: PreserveRawMessage = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a domain."""
    options = [
        enabled,
        verify_dkim,
        verify_spf,
        reject_dkim_fail,
        reject_spf_fail,
        preserve_raw_message,
    ]
    if all(value is None for value in options):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            domain = client.update_domain(
                domain_id=domain_id,
                is_enabled=enabled,
                verify_dkim=_update_flag(verify_dkim),
                verify_spf=_update_flag(verify_spf),
                reject_dkim_fail=_update_flag(reject_dkim_fail),
                reject_spf_fail=_update_flag(reject_spf_fail),
                preserve_raw_message=_update_flag(preserve_raw_message),
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
    purge: Purge = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Delete a domain (restorable), or permanently purge an already-deleted one."""
    confirm_delete("domain", domain_id, force=force, purge=purge)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_domain(domain_id, purge=purge)
            print_deleted(
                "domain",
                domain_id,
                purge=purge,
                restore_command=f"fsmtp domain restore {domain_id}",
            )
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("restore")
def restore_domain(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Restore a deleted domain and the recipients deleted with it."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            domain = client.restore_domain(domain_id)
            print_success("Domain restored")
            print_domain(domain)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


# Member subcommands
member_app = typer.Typer(help="Domain member management")
app.add_typer(member_app, name="member")


@member_app.command("list")
def list_members(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List domain members."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            members = client.list_members(domain_id)
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
