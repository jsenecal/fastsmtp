"""RuleSet and rule management commands.

Rulesets and rules are nested under a domain on the server, so every command
here takes the domain ID first. Rules have no name, no per-rule ``priority`` and
no ``is_enabled``: their evaluation order is the ruleset's ``order``, changed
with ``fsmtp rules rule reorder``.

A rule tests 1 to 16 conditions combined by ``--match all|any`` (issue #182),
given as repeatable ``--condition 'FIELD OPERATOR [VALUE]'`` and
``--not-condition`` options. ``--field/--operator/--value`` remain as the
one-condition shorthand, sent in the flat shape every server version accepts.
"""

import re
from typing import Annotated, Any

import typer

from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.commands.options import clearable_str
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
    "attachment_names",
    "attachment_types",
    "dkim_result",
    "spf_result",
)
FIELD_HEADER_PREFIX = "header:"
VALID_OPERATORS = ("equals", "contains", "regex", "starts_with", "ends_with", "exists")
VALID_ACTIONS = ("forward", "drop", "tag", "quarantine")
VALID_MATCH_MODES = ("all", "any")

CONDITION_FORMAT = "'FIELD OPERATOR [VALUE]'"


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


def _validate_match(match: str | None) -> None:
    """Reject match modes the server would reject."""
    if match is None or match in VALID_MATCH_MODES:
        return
    print_error(f"Invalid match mode. Must be one of: {', '.join(VALID_MATCH_MODES)}")
    raise typer.Exit(1)


# FIELD and OPERATOR are single words; VALUE is everything after exactly one
# separating space, so a value's own leading spaces survive.
_CONDITION_RE = re.compile(r"^\s*(\S+)\s+(\S+)(?: (.*))?$", re.DOTALL)


def parse_condition(
    spec: str, negate: bool = False, case_sensitive: bool = False
) -> dict[str, Any]:
    """Parse ``FIELD OPERATOR [VALUE]`` into the condition object the API takes.

    VALUE is everything after the single space that follows the operator,
    leading and inner spaces included, and may be omitted only for ``exists``.
    """
    parsed = _CONDITION_RE.match(spec)
    if parsed is None:
        print_error(f"Invalid condition '{spec}'. Expected {CONDITION_FORMAT}")
        raise typer.Exit(1)
    field, operator, value = parsed.group(1), parsed.group(2), parsed.group(3) or ""
    _validate_field(field)
    _validate_operator(operator)
    if operator != "exists" and value == "":
        print_error(f"Condition '{spec}' needs a VALUE for operator '{operator}'")
        raise typer.Exit(1)
    return {
        "field": field,
        "operator": operator,
        "value": value,
        "case_sensitive": case_sensitive,
        "negate": negate,
    }


def _conditions_from_options(
    conditions: list[str] | None,
    not_conditions: list[str] | None,
    case_sensitive: bool,
    shorthand: list[str | None],
) -> list[dict[str, Any]] | None:
    """Build the condition list from the options, or ``None`` if none were given.

    ``--condition`` entries come first, then ``--not-condition`` entries, each
    in the order given: the two options are collected separately, so their
    interleaving on the command line is not preserved. Order only affects which
    condition short-circuits evaluation, never the result.
    """
    specs = [(spec, False) for spec in conditions or []]
    specs += [(spec, True) for spec in not_conditions or []]
    if not specs:
        return None
    if any(option is not None for option in shorthand):
        print_error("Use --condition/--not-condition or --field/--operator/--value, not both")
        raise typer.Exit(1)
    return [parse_condition(spec, negate, case_sensitive) for spec, negate in specs]


MatchOption = Annotated[
    str | None,
    typer.Option(
        "--match",
        "-m",
        help="How conditions combine: all (every one must hold, the default) or any",
    ),
]
ConditionOption = Annotated[
    list[str] | None,
    typer.Option(
        "--condition",
        "-c",
        help=f"Condition as {CONDITION_FORMAT} (repeatable), e.g. 'from ends_with @example.com'",
    ),
]
NotConditionOption = Annotated[
    list[str] | None,
    typer.Option(
        "--not-condition",
        help=f"Negated condition as {CONDITION_FORMAT} (repeatable). True when the field is "
        "absent, and for attachments when no part matches",
    ),
]


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
    match: MatchOption = None,
    conditions: ConditionOption = None,
    not_conditions: NotConditionOption = None,
    field: Annotated[
        str | None,
        typer.Option("--field", "-F", help="Field to match (one-condition shorthand)"),
    ] = None,
    operator: Annotated[
        str | None,
        typer.Option(
            "--operator",
            "-O",
            help="Operator (equals, contains, regex, starts_with, ends_with, exists)",
        ),
    ] = None,
    value: Annotated[
        str | None,
        typer.Option("--value", "-V", help="Value to match"),
    ] = None,
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
    """Create a new rule, appended to the end of the ruleset.

    Give the rule's conditions with --condition/--not-condition, or one
    condition with --field/--operator/--value (prompted for when neither is
    given). --case-sensitive applies to every condition.
    """
    _validate_match(match)
    _validate_action(action)
    condition_list = _conditions_from_options(
        conditions, not_conditions, case_sensitive, [field, operator, value]
    )
    if condition_list is None:
        field = field if field is not None else typer.prompt("Field")
        operator = operator if operator is not None else typer.prompt("Operator")
        value = value if value is not None else typer.prompt("Value")
        _validate_field(field)
        _validate_operator(operator)

    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.create_rule(
                domain_id=domain_id,
                ruleset_id=ruleset_id,
                field=field,
                operator=operator,
                value=value,
                action=action,
                # Inside each condition when there is a list; flat otherwise.
                case_sensitive=None if condition_list else case_sensitive,
                webhook_url_override=webhook_url,
                add_tags=tags,
                preserve_raw=preserve_raw,
                conditions=condition_list,
                match=match,
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
    match: MatchOption = None,
    conditions: ConditionOption = None,
    not_conditions: NotConditionOption = None,
    field: Annotated[
        str | None,
        typer.Option(
            "--field",
            "-F",
            help="Field to match; edits a single-condition rule in place",
        ),
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
        typer.Option(
            "--webhook-url",
            "-w",
            help="Override the webhook URL for this rule; pass '' to remove the override",
        ),
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
    """Update a rule.

    --condition/--not-condition replace the rule's whole condition list.
    --field/--operator/--value edit the condition of a rule holding exactly
    one, non-negated condition; the server refuses them on any other rule.
    """
    options = [
        match,
        conditions,
        not_conditions,
        field,
        operator,
        value,
        action,
        case_sensitive,
        webhook_url,
        tags,
        preserve_raw,
    ]
    if all(option is None for option in options):
        print_error("At least one option must be provided")
        raise typer.Exit(1)

    _validate_match(match)
    _validate_field(field)
    _validate_operator(operator)
    _validate_action(action)
    condition_list = _conditions_from_options(
        conditions, not_conditions, bool(case_sensitive), [field, operator, value]
    )

    try:
        with FastSMTPClient(profile_name=profile) as client:
            rule = client.update_rule(
                domain_id=domain_id,
                rule_id=rule_id,
                field=field,
                operator=operator,
                value=value,
                action=action,
                case_sensitive=None if condition_list else case_sensitive,
                webhook_url_override=clearable_str(webhook_url),
                add_tags=tags,
                preserve_raw=preserve_raw,
                conditions=condition_list,
                match=match,
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
