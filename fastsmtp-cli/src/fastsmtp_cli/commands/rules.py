"""RuleSet and rule management commands.

Rulesets and rules are nested under a domain on the server, so every command
here takes the domain ID first. Rules have no name, no per-rule ``priority`` and
no ``is_enabled``: their evaluation order is the ruleset's ``order``, changed
with ``fsmtp rules rule reorder``.
"""

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

# Mirrors fastsmtp.schemas.rule - the server rejects anything else.
VALID_FIELDS = (
    "from",
    "to",
    "subject",
    "body",
    "has_attachment",
    "dkim_result",
    "spf_result",
)
FIELD_HEADER_PREFIX = "header:"
VALID_OPERATORS = ("equals", "contains", "regex", "starts_with", "ends_with", "exists")
VALID_ACTIONS = ("forward", "drop", "tag", "quarantine")


def _validate_field(field: str | None) -> None:
    """Reject fields the server would reject, before spending a round-trip."""
    if field is None or field in VALID_FIELDS or field.startswith(FIELD_HEADER_PREFIX):
        return
    print_error(
        f"Invalid field. Must be one of: {', '.join(VALID_FIELDS)}, "
        f"or {FIELD_HEADER_PREFIX}X-Header-Name"
    )
    raise typer.Exit(1)


def _validate_operator(operator: str | None) -> None:
    """Reject operators the server would reject."""
    if operator is None or operator in VALID_OPERATORS:
        return
    print_error(f"Invalid operator. Must be one of: {', '.join(VALID_OPERATORS)}")
    raise typer.Exit(1)


def _validate_action(action: str | None) -> None:
    """Reject actions the server would reject."""
    if action is None or action in VALID_ACTIONS:
        return
    print_error(f"Invalid action. Must be one of: {', '.join(VALID_ACTIONS)}")
    raise typer.Exit(1)


# RuleSet commands
@app.command("list")
def list_rulesets(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List rulesets for a domain."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            rulesets = client.list_rulesets(domain_id)
            if not rulesets:
                print_error("No rulesets found")
                return
            print_rulesets_table(rulesets)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("get")
def get_ruleset(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get ruleset details with rules."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            ruleset = client.get_ruleset(domain_id, ruleset_id)
            print_ruleset(ruleset)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("create")
def create_ruleset(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    name: Annotated[str, typer.Argument(help="RuleSet name")],
    priority: Annotated[
        int,
        typer.Option("--priority", "-P", help="Priority (higher = first)"),
    ] = 0,
    stop_on_match: Annotated[
        bool,
        typer.Option(
            "--stop-on-match/--no-stop-on-match",
            help="Stop evaluating later rulesets once a rule here matches",
        ),
    ] = True,
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
                priority=priority,
                stop_on_match=stop_on_match,
            )
            print_success(f"RuleSet '{name}' created")
            print_ruleset(ruleset)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("update")
def update_ruleset(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="New name"),
    ] = None,
    priority: Annotated[
        int | None,
        typer.Option("--priority", "-P", help="Priority"),
    ] = None,
    stop_on_match: Annotated[
        bool | None,
        typer.Option("--stop-on-match/--no-stop-on-match", help="Stop on match"),
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
    if all(value is None for value in [name, priority, stop_on_match, enabled]):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            ruleset = client.update_ruleset(
                domain_id=domain_id,
                ruleset_id=ruleset_id,
                name=name,
                priority=priority,
                stop_on_match=stop_on_match,
                is_enabled=enabled,
            )
            print_success("RuleSet updated")
            print_ruleset(ruleset)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@app.command("delete")
def delete_ruleset(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
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
            client.delete_ruleset(domain_id, ruleset_id)
            print_success(f"RuleSet {ruleset_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


# Rule subcommands
rule_app = typer.Typer(help="Rule management within a ruleset")
app.add_typer(rule_app, name="rule")


@rule_app.command("list")
def list_rules(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """List rules in a ruleset."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            rules = client.list_rules(domain_id, ruleset_id)
            if not rules:
                print_error("No rules found")
                return
            print_rules_table(rules)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("get")
def get_rule(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    rule_id: Annotated[str, typer.Argument(help="Rule ID")],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Get rule details."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.get_rule(domain_id, ruleset_id, rule_id)
            print_rule(rule)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("create")
def create_rule(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    field: Annotated[
        str,
        typer.Option("--field", "-F", help="Field to match", prompt=True),
    ],
    operator: Annotated[
        str,
        typer.Option(
            "--operator",
            "-O",
            help="Operator (equals, contains, regex, starts_with, ends_with, exists)",
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
    case_sensitive: Annotated[
        bool,
        typer.Option("--case-sensitive/--ignore-case", help="Match case sensitively"),
    ] = False,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", "-w", help="Override the webhook URL for this rule"),
    ] = None,
    tags: Annotated[
        list[str] | None,
        typer.Option("--tag", "-t", help="Tag to add when the rule matches (repeatable)"),
    ] = None,
    preserve_raw: Annotated[
        bool,
        typer.Option(
            "--preserve-raw/--no-preserve-raw",
            help="Preserve the raw MIME message in S3 when this rule matches",
        ),
    ] = False,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Create a new rule, appended to the end of the ruleset."""
    _validate_field(field)
    _validate_operator(operator)
    _validate_action(action)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.create_rule(
                domain_id=domain_id,
                ruleset_id=ruleset_id,
                field=field,
                operator=operator,
                value=value,
                action=action,
                case_sensitive=case_sensitive,
                webhook_url_override=webhook_url,
                add_tags=tags,
                preserve_raw=preserve_raw,
            )
            print_success("Rule created")
            print_rule(rule)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("update")
def update_rule(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    rule_id: Annotated[str, typer.Argument(help="Rule ID")],
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
    case_sensitive: Annotated[
        bool | None,
        typer.Option("--case-sensitive/--ignore-case", help="Match case sensitively"),
    ] = None,
    webhook_url: Annotated[
        str | None,
        typer.Option("--webhook-url", "-w", help="Override the webhook URL for this rule"),
    ] = None,
    tags: Annotated[
        list[str] | None,
        typer.Option("--tag", "-t", help="Tags to add when the rule matches (replaces existing)"),
    ] = None,
    preserve_raw: Annotated[
        bool | None,
        typer.Option(
            "--preserve-raw/--no-preserve-raw",
            help="Preserve the raw MIME message in S3 when this rule matches",
        ),
    ] = None,
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Update a rule."""
    options = [field, operator, value, action, case_sensitive, webhook_url, tags, preserve_raw]
    if all(option is None for option in options):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    _validate_field(field)
    _validate_operator(operator)
    _validate_action(action)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.update_rule(
                domain_id=domain_id,
                rule_id=rule_id,
                field=field,
                operator=operator,
                value=value,
                action=action,
                case_sensitive=case_sensitive,
                webhook_url_override=webhook_url,
                add_tags=tags,
                preserve_raw=preserve_raw,
            )
            print_success("Rule updated")
            print_rule(rule)
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("delete")
def delete_rule(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
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
            client.delete_rule(domain_id, rule_id)
            print_success(f"Rule {rule_id} deleted")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e


@rule_app.command("reorder")
def reorder_rules(
    domain_id: Annotated[str, typer.Argument(help="Domain ID")],
    ruleset_id: Annotated[str, typer.Argument(help="RuleSet ID")],
    rule_ids: Annotated[
        list[str],
        typer.Argument(help="Every rule ID in the ruleset, in the desired order"),
    ],
    profile: Annotated[
        str | None,
        typer.Option("--profile", "-p", help="Profile to use"),
    ] = None,
) -> None:
    """Set the evaluation order of a ruleset's rules."""
    try:
        with FastSMTPClient(profile_name=profile) as client:
            client.reorder_rules(domain_id, ruleset_id, rule_ids)
            print_success("Rules reordered")
    except APIError as e:
        print_error(e.detail)
        raise typer.Exit(1) from e
