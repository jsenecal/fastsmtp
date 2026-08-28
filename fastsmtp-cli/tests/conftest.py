"""Shared test configuration for the CLI package.

``test_api_contract`` imports ``fastsmtp.main`` to build the server's OpenAPI
document, and that module resolves settings at import time. Without these
variables the import raises before any fixture argument can supply them, so the
contract tests error out whenever this package's tests run on their own rather
than as part of the full suite.
"""

import os

import pytest

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")
os.environ.setdefault("FASTSMTP_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

CONSOLE_WIDTH = 80


@pytest.fixture(autouse=True)
def deterministic_console(monkeypatch):
    """Render as if piped to an 80-column pipe, whatever terminal ran the suite.

    ``fastsmtp_cli.output`` builds both consoles at module scope, so each one
    resolves its colour system and its width from the environment on import.
    Two variables then decide what every assertion in ``test_output`` sees:

    * ``FORCE_COLOR`` - which editors and agent harnesses set routinely - makes
      rich emit ANSI escapes even though pytest's captured stdout is no tty.
    * ``COLUMNS`` decides whether a table cell is padded or truncated to an
      ellipsis.

    CI sets neither, so both were invisible there and failed a clean ``main``
    on a developer's machine instead. See issue #159.

    Pinning the attributes rather than deleting the environment variables is
    deliberate: ``_color_system`` is resolved in ``Console.__init__`` and never
    consulted again, so unsetting ``FORCE_COLOR`` from a fixture is already too
    late for a console built at import time - and which module imported
    ``output`` first is not something this file can order. Mutating the two
    console objects in place reaches every reference to them, including the
    ones ``test_output`` imported by value.
    """
    from fastsmtp_cli.output import console, error_console

    for target in (console, error_console):
        monkeypatch.setattr(target, "_color_system", None)
        monkeypatch.setattr(target, "_width", CONSOLE_WIDTH)
