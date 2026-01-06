"""RuleSet and rule management commands."""

from typing import Annotated

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.output import (
    print_error,
    print_rule,
    print_rules_table,
    print_ruleset,
    print_rulesets_table,
    print_success,
)

app = typer.Typer(help="RuleSet and rule management")


# RuleSet commands
@app.command("list")
def list_rulesets(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    limit: Annotated[int, typer.Option("--limit", "-l", help="Max results")] = 50,
    offset: Annotated[int, typer.Option("--offset", "-o", help="Offset")] = 0,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List rulesets for a domain."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            rulesets = client.list_rulesets(domain_id, limit=limit, offset=offset)
            if not rulesets:
                print_error("No rulesets found")
                return
            print_rulesets_table(rulesets)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("get")
def get_ruleset(
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get ruleset details with rules."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            ruleset = client.get_ruleset(ruleset_id)
            print_ruleset(ruleset)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("create")
def create_ruleset(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    name: Annotated[str, typer.Argument(help="RuleSet name")],
    description: Annotated[
        str | None,
        typer.Option("--description", "-d", help="Description"),
    ] = None,
    priority: Annotated[
        int,
        typer.Option("--priority", "-P", help="Priority (higher = first)"),
    ] = 0,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new ruleset."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            ruleset = client.create_ruleset(
                domain_id=domain_id,
                name=name,
                description=description,
                priority=priority,
            )
            print_success(f"RuleSet '{name}' created")
            print_ruleset(ruleset)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("update")
def update_ruleset(
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="New name"),
    ] = None,
    description: Annotated[
        str | None,
        typer.Option("--description", "-d", help="Description"),
    ] = None,
    priority: Annotated[
        int | None,
        typer.Option("--priority", "-P", help="Priority"),
    ] = None,
    enabled: Annotated[
        bool | None,
        typer.Option("--enabled/--disabled", help="Enable or disable ruleset"),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a ruleset."""
    if all(v is None for v in [name, description, priority, enabled]):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            ruleset = client.update_ruleset(
                ruleset_id=ruleset_id,
                name=name,
                description=description,
                priority=priority,
                is_enabled=enabled,
            )
            print_success("RuleSet updated")
            print_ruleset(ruleset)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("delete")
def delete_ruleset(
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Delete a ruleset."""
    if not force:
        confirm = typer.confirm(f"Delete ruleset {ruleset_id}?")
        if not confirm:
            raise typer.Exit(0)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_ruleset(ruleset_id)
            print_success(f"RuleSet {ruleset_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


# Rule subcommands
rule_app = typer.Typer(help="Rule management within a ruleset")
app.add_typer(rule_app, name="rule")


@rule_app.command("list")
def list_rules(
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List rules in a ruleset."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            rules = client.list_rules(ruleset_id)
            if not rules:
                print_error("No rules found")
                return
            print_rules_table(rules)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("get")
def get_rule(
    rule_id: Annotated[str, typer.Argument(help="Rule ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get rule details."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.get_rule(rule_id)
            print_rule(rule)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("create")
def create_rule(
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    name: Annotated[str, typer.Argument(help="Rule name")],
    field: Annotated[
        str,
        typer.Option("--field", "-F", help="Field to match", prompt=True),
    ],
    operator: Annotated[
        str,
        typer.Option(
            "--operator",
            "-O",
            help="Operator (equals, contains, regex, etc.)",
            prompt=True,
        ),
    ],
    value: Annotated[
        str,
        typer.Option("--value", "-V", help="Value to match", prompt=True),
    ],
    action: Annotated[
        str,
        typer.Option("--action", "-a", help="Action (forward, drop, tag, quarantine)"),
    ] = "forward",
    priority: Annotated[
        int,
        typer.Option("--priority", "-P", help="Priority (higher = first)"),
    ] = 0,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new rule."""
    valid_operators = [
        "equals",
        "not_equals",
        "contains",
        "not_contains",
        "starts_with",
        "ends_with",
        "regex",
        "exists",
        "not_exists",
    ]
    if operator not in valid_operators:
        print_error(f"Invalid operator. Must be one of: {', '.join(valid_operators)}")
        raise typer.Exit(1)

    valid_actions = ["forward", "drop", "tag", "quarantine"]
    if action not in valid_actions:
        print_error(f"Invalid action. Must be one of: {', '.join(valid_actions)}")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.create_rule(
                ruleset_id=ruleset_id,
                name=name,
                field=field,
                operator=operator,
                value=value,
                action=action,
                priority=priority,
            )
            print_success(f"Rule '{name}' created")
            print_rule(rule)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("update")
def update_rule(
    rule_id: Annotated[str, typer.Argument(help="Rule ID")],
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="New name"),
    ] = None,
    field: Annotated[
        str | None,
        typer.Option("--field", "-F", help="Field to match"),
    ] = None,
    operator: Annotated[
        str | None,
        typer.Option("--operator", "-O", help="Operator"),
    ] = None,
    value: Annotated[
        str | None,
        typer.Option("--value", "-V", help="Value to match"),
    ] = None,
    action: Annotated[
        str | None,
        typer.Option("--action", "-a", help="Action"),
    ] = None,
    priority: Annotated[
        int | None,
        typer.Option("--priority", "-P", help="Priority"),
    ] = None,
    enabled: Annotated[
        bool | None,
        typer.Option("--enabled/--disabled", help="Enable or disable rule"),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a rule."""
    if all(v is None for v in [name, field, operator, value, action, priority, enabled]):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.update_rule(
                rule_id=rule_id,
                name=name,
                field=field,
                operator=operator,
                value=value,
                action=action,
                priority=priority,
                is_enabled=enabled,
            )
            print_success("Rule updated")
            print_rule(rule)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("delete")
def delete_rule(
    rule_id: Annotated[str, typer.Argument(help="Rule ID")],
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Skip confirmation"),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Delete a rule."""
    if not force:
        confirm = typer.confirm(f"Delete rule {rule_id}?")
        if not confirm:
            raise typer.Exit(0)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.delete_rule(rule_id)
            print_success(f"Rule {rule_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
