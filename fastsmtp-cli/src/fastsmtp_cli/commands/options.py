"""Shared option aliases and helpers for the command modules."""

from typing import Annotated

import typer

from fastsmtp_cli.client import UNSET, NullableStr

#: ``--include-deleted`` on every list/get that can show tombstones. The server
#: gates the flag at the delete role for that resource, so a caller below it
#: gets a 403 whether or not a tombstone exists.
IncludeDeleted = Annotated[
    bool,
    typer.Option("--include-deleted", help="Also show deleted (restorable) entries"),
]

#: The same flag on ``auth keys``: keys are never restorable, and the listing
#: also covers keys retired before soft delete existed.
IncludeDeletedKeys = Annotated[
    bool,
    typer.Option(
        "--include-deleted", help="Also show deleted and retired keys (keys cannot be restored)"
    ),
]

#: The same flag on ``ops log list``: log rows are never deleted, so the flag
#: only resolves a deleted domain (owner or superuser) to read its history.
IncludeDeletedLogs = Annotated[
    bool,
    typer.Option(
        "--include-deleted",
        help="Read the history of a deleted domain (owner or superuser); log rows themselves "
        "are never deleted",
    ),
]

#: ``--purge`` on every delete. A purge is a second step: it only works on a row
#: that is already deleted (the server answers 409 otherwise), and it runs the
#: hard-delete cascades that soft delete exists to avoid.
Purge = Annotated[
    bool,
    typer.Option(
        "--purge",
        help="Permanently delete an already-deleted entry (superuser only, cannot be undone)",
    ),
]


def confirm_delete(kind: str, label: str, *, force: bool, purge: bool) -> None:
    """Ask before a delete unless ``--force``; exit 0 when the operator declines.

    Shared by the user, domain and recipient ``delete`` commands. A soft
    delete keeps the pre-0.5.0 prompt; a purge gets its own, spelling out that
    it cannot be undone.
    """
    if force:
        return
    if purge:
        prompt = f"Permanently delete {kind} {label}? This cannot be undone."
    else:
        prompt = f"Delete {kind} {label}?"
    if not typer.confirm(prompt):
        raise typer.Exit(0)


def clearable_str(option: str | None) -> NullableStr:
    """Map a nullable-string option onto the client's tri-state value.

    CLI-wide convention for options backed by a nullable string column: leaving
    the option off (``None``) leaves the column untouched, passing an empty
    string (``--option ''``) clears it (the client sends an explicit JSON
    null), and any other value sets it.

    This is the string counterpart of the ``true``/``false``/``inherit``
    tri-state used for nullable boolean flags (see ``commands/domains.py``);
    strings need no enum because the empty string is not an otherwise
    meaningful value for these columns.
    """
    if option is None:
        return UNSET
    if option == "":
        return None
    return option
