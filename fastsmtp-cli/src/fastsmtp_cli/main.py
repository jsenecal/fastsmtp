"""FastSMTP CLI - Remote CLI client for FastSMTP server."""

from typing import Annotated

import typer

from fastsmtp_cli import __version__
from fastsmtp_cli.commands import auth, config, domains, operations, recipients, rules
from fastsmtp_cli.output import console

app = typer.Typer(
    name="fsmtp",
    help="FastSMTP CLI - Remote CLI client for FastSMTP server",
    no_args_is_help=True,
)

# Global options
ProfileOption = Annotated[
    str | None,
    typer.Option("--profile", "-p", help="Profile to use", envvar="FSMTP_PROFILE"),
]


def version_callback(value: bool) -> None:
    """Print version and exit."""
    if value:
        console.print(f"FastSMTP CLI version {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            "-V",
            callback=version_callback,
            is_eager=True,
            help="Show version and exit",
        ),
    ] = False,
) -> None:
    """FastSMTP CLI - Remote CLI client for FastSMTP server."""
    pass


# Register command groups
app.add_typer(config.app, name="config", help="Manage CLI configuration and profiles")
app.add_typer(auth.app, name="auth", help="Authentication and API key management")
app.add_typer(domains.app, name="domain", help="Domain management")
app.add_typer(recipients.app, name="recipient", help="Recipient management")
app.add_typer(rules.app, name="rules", help="RuleSet and rule management")
app.add_typer(operations.app, name="ops", help="Operations (health, logs, test)")


if __name__ == "__main__":
    app()
