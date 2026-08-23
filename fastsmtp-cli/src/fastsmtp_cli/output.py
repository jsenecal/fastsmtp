"""Output formatting utilities for CLI."""

import json
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.json import JSON
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()
error_console = Console(stderr=True)


def field(value: Any, placeholder: str = "-") -> str:
    """Render a server-supplied value as literal text.

    Rich parses plain strings as markup, so a value containing square brackets
    would restyle the output — or crash the command with ``MarkupError`` on an
    unmatched closing tag. Escaping here keeps server text literal while the
    markup the formatters build deliberately (``yes_no``, ``tri_state``, the
    ``status_style`` wrappers) still parses. ``None`` and empty values render
    as the placeholder.
    """
    if value is None or value == "":
        return placeholder
    return escape(str(value))


def short_id(value: Any) -> str:
    """Render the first 8 characters of a server identifier."""
    if value is None or value == "":
        return "-"
    return field(str(value)[:8] + "...")


def _parse_datetime(value: str) -> datetime | None:
    """Parse a server timestamp string, or ``None`` when it is not ISO 8601."""
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def format_datetime(dt: str | datetime | None) -> str:
    """Format a datetime for display."""
    if dt is None:
        return "-"
    if isinstance(dt, str):
        parsed = _parse_datetime(dt)
        if parsed is None:
            # Not a timestamp we understand -- show the server's text literally.
            return escape(dt)
    else:
        parsed = dt
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _format_expiry(expires: str | datetime | None) -> str:
    """Render an API key's expiry as a fully-styled cell.

    Shared by ``print_api_keys_table`` and ``print_api_key`` so the two views
    cannot drift. ``None`` means the key never expires. The timestamp is parsed
    once and reused for both the expired-vs-not comparison and the display; a
    value the server sends that is not a timestamp is shown literally (escaped,
    like ``format_datetime``'s fallback) with no expiry styling, instead of
    crashing the command.
    """
    if not expires:
        return "[dim]Never[/dim]"
    if isinstance(expires, str):
        parsed = _parse_datetime(expires)
        if parsed is None:
            return field(expires)
    else:
        parsed = expires
    formatted = format_datetime(parsed)
    if parsed < datetime.now(parsed.tzinfo):
        return f"[red]{formatted}[/red]"
    return formatted


def truncate(text: str | None, max_length: int = 50) -> str:
    """Truncate text with ellipsis."""
    if text is None:
        return "-"
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def status_style(status: str) -> str:
    """Get rich style for a status string."""
    status_lower = status.lower()
    if status_lower in ("ok", "pass", "success", "delivered", "active", "enabled"):
        return "green"
    if status_lower in ("fail", "failed", "error", "exhausted", "disabled"):
        return "red"
    if status_lower in ("pending", "queued", "retrying", "warning"):
        return "yellow"
    return "white"


def yes_no(value: Any) -> str:
    """Render a boolean as coloured Yes/No."""
    return "[green]Yes[/green]" if value else "[red]No[/red]"


def tri_state(value: bool | None) -> str:
    """Render a nullable server setting, where null means "inherit the default"."""
    if value is None:
        return "[dim]inherit[/dim]"
    return "[green]Yes[/green]" if value else "[red]No[/red]"


def format_mapping(mapping: dict | None) -> str:
    """Render a string mapping (webhook headers) on one line."""
    if not mapping:
        return "-"
    return ", ".join(f"{key}={value}" for key, value in mapping.items())


def print_json(data: Any) -> None:
    """Print data as formatted JSON."""
    console.print(JSON(json.dumps(data, indent=2, default=str)))


def print_error(message: str) -> None:
    """Print an error message.

    Server details can contain square brackets (validation messages list valid
    values that way), so the message is escaped rather than parsed as markup.
    """
    error_console.print(f"[red]Error:[/red] {escape(str(message))}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[green]{escape(str(message))}[/green]")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[yellow]{escape(str(message))}[/yellow]")


def print_info(message: str) -> None:
    """Print an info message."""
    console.print(f"[blue]{escape(str(message))}[/blue]")


# Table formatters for different resource types


def print_health(data: dict) -> None:
    """Print health check result."""
    status = data.get("status", "unknown")
    style = status_style(status)

    panel = Panel(
        f"[{style}]Status: {field(status)}[/{style}]\n"
        f"Version: {field(data.get('version', 'unknown'))}\n"
        f"Instance: {field(data.get('instance_id', 'unknown'))}",
        title="Health Check",
    )
    console.print(panel)


def print_ready(data: dict) -> None:
    """Print readiness check result."""
    status = data.get("status", "unknown")
    db_status = data.get("database", "unknown")

    panel = Panel(
        f"[{status_style(status)}]Status: {field(status)}[/{status_style(status)}]\n"
        f"[{status_style(db_status)}]Database: {field(db_status)}[/{status_style(db_status)}]",
        title="Readiness Check",
    )
    console.print(panel)


def print_whoami(data: dict) -> None:
    """Print current user info (server schema: user, domains, is_root)."""
    user = data.get("user", {})

    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("User ID", field(user.get("id")))
    table.add_row("Username", field(user.get("username")))
    table.add_row("Email", field(user.get("email")))
    table.add_row("Superuser", yes_no(user.get("is_superuser")))
    table.add_row("Root Key", yes_no(data.get("is_root")))
    table.add_row("Domains", field(", ".join(data.get("domains", []))))

    console.print(Panel(table, title="Current Session"))


def print_users_table(users: list[dict]) -> None:
    """Print users as a table."""
    table = Table(title="Users")

    table.add_column("ID", style="dim")
    table.add_column("Username")
    table.add_column("Email")
    table.add_column("Superuser")
    table.add_column("Active")
    table.add_column("Created")

    for user in users:
        table.add_row(
            short_id(user.get("id")),
            field(user.get("username")),
            field(user.get("email")),
            yes_no(user.get("is_superuser")),
            yes_no(user.get("is_active")),
            format_datetime(user.get("created_at")),
        )

    console.print(table)


def print_user(user: dict) -> None:
    """Print a single user."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("ID", field(user.get("id")))
    table.add_row("Username", field(user.get("username")))
    table.add_row("Email", field(user.get("email")))
    table.add_row("Superuser", yes_no(user.get("is_superuser")))
    table.add_row("Active", yes_no(user.get("is_active")))
    table.add_row("Created", format_datetime(user.get("created_at")))
    table.add_row("Updated", format_datetime(user.get("updated_at")))

    console.print(Panel(table, title="User Details"))


def print_api_keys_table(keys: list[dict]) -> None:
    """Print API keys as a table."""
    table = Table(title="API Keys")

    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Scopes")
    table.add_column("Expires")
    table.add_column("Last Used")
    table.add_column("Created")

    for key in keys:
        table.add_row(
            short_id(key.get("id")),
            field(key.get("name")),
            field(truncate(", ".join(key.get("scopes", [])), 30), placeholder="all"),
            _format_expiry(key.get("expires_at")),
            format_datetime(key.get("last_used_at")) if key.get("last_used_at") else "-",
            format_datetime(key.get("created_at")),
        )

    console.print(table)


def print_api_key(key: dict, show_secret: bool = False) -> None:
    """Print a single API key."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("ID", field(key.get("id")))
    table.add_row("Name", field(key.get("name")))
    table.add_row("Scopes", field(", ".join(key.get("scopes", [])), placeholder="all"))
    table.add_row("Expires", _format_expiry(key.get("expires_at")))
    table.add_row("Created", format_datetime(key.get("created_at")))

    if show_secret and key.get("key"):
        table.add_row("", "")
        table.add_row("[bold yellow]API Key[/bold yellow]", f"[bold]{escape(key['key'])}[/bold]")
        table.add_row("", "[dim]Save this key - it won't be shown again![/dim]")

    console.print(Panel(table, title="API Key"))


def print_domains_table(domains: list[dict]) -> None:
    """Print domains as a table."""
    table = Table(title="Domains")

    table.add_column("ID", style="dim")
    table.add_column("Domain")
    table.add_column("Enabled")
    table.add_column("DKIM")
    table.add_column("SPF")
    table.add_column("Preserve Raw")
    table.add_column("Created")

    for domain in domains:
        table.add_row(
            short_id(domain.get("id")),
            field(domain.get("domain_name")),
            yes_no(domain.get("is_enabled")),
            tri_state(domain.get("verify_dkim")),
            tri_state(domain.get("verify_spf")),
            tri_state(domain.get("preserve_raw_message")),
            format_datetime(domain.get("created_at")),
        )

    console.print(table)


def print_domain(domain: dict) -> None:
    """Print a single domain."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("ID", field(domain.get("id")))
    table.add_row("Domain", field(domain.get("domain_name")))
    table.add_row("Enabled", yes_no(domain.get("is_enabled")))
    table.add_row("Verify DKIM", tri_state(domain.get("verify_dkim")))
    table.add_row("Verify SPF", tri_state(domain.get("verify_spf")))
    table.add_row("Reject DKIM Fail", tri_state(domain.get("reject_dkim_fail")))
    table.add_row("Reject SPF Fail", tri_state(domain.get("reject_spf_fail")))
    table.add_row("Preserve Raw", tri_state(domain.get("preserve_raw_message")))
    table.add_row("Created", format_datetime(domain.get("created_at")))
    table.add_row("Updated", format_datetime(domain.get("updated_at")))

    console.print(Panel(table, title="Domain Details"))


def print_members_table(members: list[dict]) -> None:
    """Print domain members as a table."""
    table = Table(title="Domain Members")

    table.add_column("User ID", style="dim")
    table.add_column("Username")
    table.add_column("Role")
    table.add_column("Joined")

    for member in members:
        role = member.get("role", "-")
        role_style = "yellow" if role == "owner" else "cyan" if role == "admin" else "white"

        table.add_row(
            short_id(member.get("user_id")),
            field(member.get("username")),
            f"[{role_style}]{field(role)}[/{role_style}]",
            format_datetime(member.get("created_at")),
        )

    console.print(table)


def print_recipients_table(recipients: list[dict]) -> None:
    """Print recipients as a table."""
    table = Table(title="Recipients")

    table.add_column("ID", style="dim")
    table.add_column("Address")
    table.add_column("Webhook URL")
    table.add_column("Headers")
    table.add_column("Enabled")

    for recipient in recipients:
        local_part = recipient.get("local_part")
        address = field(local_part) if local_part else "[dim]*[/dim] (catch-all)"

        table.add_row(
            short_id(recipient.get("id")),
            address,
            field(truncate(recipient.get("webhook_url"), 40)),
            field(truncate(format_mapping(recipient.get("webhook_headers")), 20)),
            yes_no(recipient.get("is_enabled")),
        )

    console.print(table)


def print_recipient(recipient: dict) -> None:
    """Print a single recipient."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    local_part = recipient.get("local_part")

    table.add_row("ID", field(recipient.get("id")))
    table.add_row("Local Part", field(local_part) if local_part else "[dim]* (catch-all)[/dim]")
    table.add_row("Webhook URL", field(recipient.get("webhook_url")))
    table.add_row("Webhook Headers", field(format_mapping(recipient.get("webhook_headers"))))
    table.add_row("Enabled", yes_no(recipient.get("is_enabled")))
    table.add_row("Created", format_datetime(recipient.get("created_at")))

    console.print(Panel(table, title="Recipient Details"))


def print_rulesets_table(rulesets: list[dict]) -> None:
    """Print rulesets as a table."""
    table = Table(title="RuleSets")

    table.add_column("ID", style="dim")
    table.add_column("Name")
    table.add_column("Priority")
    table.add_column("Stop on Match")
    table.add_column("Rules")
    table.add_column("Enabled")

    for ruleset in rulesets:
        table.add_row(
            short_id(ruleset.get("id")),
            field(ruleset.get("name")),
            str(ruleset.get("priority", 0)),
            yes_no(ruleset.get("stop_on_match")),
            str(len(ruleset.get("rules", []))),
            yes_no(ruleset.get("is_enabled")),
        )

    console.print(table)


def print_ruleset(ruleset: dict) -> None:
    """Print a single ruleset with its rules."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("ID", field(ruleset.get("id")))
    table.add_row("Name", field(ruleset.get("name")))
    table.add_row("Priority", str(ruleset.get("priority", 0)))
    table.add_row("Stop on Match", yes_no(ruleset.get("stop_on_match")))
    table.add_row("Enabled", yes_no(ruleset.get("is_enabled")))
    table.add_row("Created", format_datetime(ruleset.get("created_at")))

    console.print(Panel(table, title="RuleSet Details"))

    # Print rules if present
    rules = ruleset.get("rules", [])
    if rules:
        print_rules_table(rules)


def print_rules_table(rules: list[dict]) -> None:
    """Print rules as a table."""
    table = Table(title="Rules")

    table.add_column("ID", style="dim")
    table.add_column("Order")
    table.add_column("Condition")
    table.add_column("Action")
    table.add_column("Tags")
    table.add_column("Preserve Raw")

    for rule in rules:
        field_name = rule.get("field", "-")
        op = rule.get("operator", "-")
        val = rule.get("value", "-")
        condition = f"{field_name} {op} '{val}'"

        table.add_row(
            short_id(rule.get("id")),
            str(rule.get("order", 0)),
            field(truncate(condition, 35)),
            field(rule.get("action")),
            field(", ".join(rule.get("add_tags") or [])),
            yes_no(rule.get("preserve_raw")),
        )

    console.print(table)


def print_rule(rule: dict) -> None:
    """Print a single rule."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("ID", field(rule.get("id")))
    table.add_row("RuleSet ID", field(rule.get("ruleset_id")))
    table.add_row("Order", str(rule.get("order", 0)))
    table.add_row("Field", field(rule.get("field")))
    table.add_row("Operator", field(rule.get("operator")))
    table.add_row("Value", field(rule.get("value")))
    table.add_row("Case Sensitive", yes_no(rule.get("case_sensitive")))
    table.add_row("Action", field(rule.get("action")))
    table.add_row("Webhook Override", field(rule.get("webhook_url_override")))
    table.add_row("Add Tags", field(", ".join(rule.get("add_tags") or [])))
    table.add_row("Preserve Raw", yes_no(rule.get("preserve_raw")))
    table.add_row("Created", format_datetime(rule.get("created_at")))

    console.print(Panel(table, title="Rule Details"))


def print_delivery_logs_table(logs: list[dict]) -> None:
    """Print delivery logs as a table."""
    table = Table(title="Delivery Logs")

    table.add_column("ID", style="dim")
    table.add_column("Message ID")
    table.add_column("Recipient")
    table.add_column("Status")
    table.add_column("Attempts")
    table.add_column("Created")

    for log in logs:
        status = log.get("status", "-")

        table.add_row(
            short_id(log.get("id")),
            field(truncate(log.get("message_id"), 25)),
            short_id(log.get("recipient_id")),
            f"[{status_style(status)}]{field(status)}[/{status_style(status)}]",
            str(log.get("attempts", 0)),
            format_datetime(log.get("created_at")),
        )

    console.print(table)


def print_delivery_log(log: dict) -> None:
    """Print a single delivery log."""
    table = Table(show_header=False, box=None)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    status = log.get("status", "-")

    table.add_row("ID", field(log.get("id")))
    table.add_row("Message ID", field(log.get("message_id")))
    table.add_row("Recipient ID", field(log.get("recipient_id")))
    table.add_row("Webhook URL", field(log.get("webhook_url")))
    table.add_row("Status", f"[{status_style(status)}]{field(status)}[/{status_style(status)}]")
    table.add_row("Attempts", str(log.get("attempts", 0)))
    table.add_row("HTTP Status", str(log.get("last_status_code") or "-"))
    table.add_row("DKIM", field(log.get("dkim_result")))
    table.add_row("SPF", field(log.get("spf_result")))
    table.add_row("Error", field(log.get("last_error")))
    table.add_row("Created", format_datetime(log.get("created_at")))
    table.add_row("Next Retry", format_datetime(log.get("next_retry_at")))

    console.print(Panel(table, title="Delivery Log Details"))

    # Print payload if present
    payload = log.get("payload")
    if payload:
        console.print("\n[bold]Payload:[/bold]")
        print_json(payload)


def print_test_webhook_result(result: dict) -> None:
    """Print test webhook result."""
    success = result.get("success", False)
    status_code = result.get("status_code")
    error = result.get("error")
    response_time = result.get("response_time_ms") or 0

    if success:
        text = Text()
        text.append("SUCCESS", style="bold green")
        text.append(f"\nStatus Code: {status_code}")
        text.append(f"\nResponse Time: {response_time:.2f}ms")
    else:
        text = Text()
        text.append("FAILED", style="bold red")
        if status_code:
            text.append(f"\nStatus Code: {status_code}")
        if error:
            text.append(f"\nError: {error}")
        text.append(f"\nResponse Time: {response_time:.2f}ms")

    console.print(Panel(text, title="Webhook Test Result"))


def print_profiles_table(
    profiles: dict,
    default_profile: str,
    show_keys: bool = False,
) -> None:
    """Print profiles as a table."""
    table = Table(title="Profiles")

    table.add_column("Name")
    table.add_column("URL")
    table.add_column("Timeout")
    table.add_column("SSL Verify")
    if show_keys:
        table.add_column("API Key")

    for name, profile in profiles.items():
        is_default = name == default_profile
        name_display = f"[bold]{field(name)}[/bold] (default)" if is_default else field(name)

        row = [
            name_display,
            field(profile.url),
            f"{profile.timeout}s",
            "[green]Yes[/green]" if profile.verify_ssl else "[red]No[/red]",
        ]

        if show_keys:
            key = profile.api_key
            if key:
                row.append(field(truncate(key, 20)))
            else:
                row.append("[dim]Not set[/dim]")

        table.add_row(*row)

    console.print(table)
