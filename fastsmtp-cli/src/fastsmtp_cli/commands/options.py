"""Shared helpers for mapping Typer option values to client arguments."""

from fastsmtp_cli.client import UNSET, NullableStr


def clearable_str(option: str | None) -> NullableStr:
    """Map a nullable-string option onto the client's tri-state value.

    CLI-wide convention for options backed by a nullable string column: leaving
    the option off (``None``) leaves the column untouched, passing an empty
    string (``--option ''``) clears it — the client sends an explicit JSON
    null — and any other value sets it.

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
