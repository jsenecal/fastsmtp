"""Rules engine for email processing."""

import logging
import uuid
from dataclasses import dataclass, field
from email.message import Message

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import Domain, Rule, RuleSet
from fastsmtp.rules.conditions import evaluate_condition
from fastsmtp.smtp.validation import EmailAuthResult

logger = logging.getLogger(__name__)


@dataclass
class RuleMatch:
    """Result of a rule match."""

    rule_id: uuid.UUID
    ruleset_id: uuid.UUID
    action: str
    tags: list[str] = field(default_factory=list)
    webhook_url_override: str | None = None
    preserve_raw: bool = False


@dataclass
class RuleEvaluationResult:
    """Result of evaluating all rules for an email."""

    matches: list[RuleMatch] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    action: str = "forward"  # forward, drop, quarantine
    webhook_url_override: str | None = None
    preserve_raw: bool = False

    @property
    def should_drop(self) -> bool:
        """Check if the email should be dropped."""
        return self.action == "drop"

    @property
    def should_quarantine(self) -> bool:
        """Check if the email should be quarantined."""
        return self.action == "quarantine"


def extract_field_value(
    field_name: str,
    message: Message,
    payload: dict,
    auth_result: EmailAuthResult | None = None,
    settings: Settings | None = None,
) -> str | None:
    """Extract a field value from an email message.

    Args:
        field_name: Field to extract (from, to, subject, header:X-*, etc.)
        message: Parsed email message
        payload: Extracted email payload
        auth_result: Email authentication result
        settings: Application settings

    Returns:
        Field value or None if not found
    """
    settings = settings or get_settings()

    # Handle special fields
    if field_name == "from":
        return message.get("From", "")
    elif field_name == "to":
        return message.get("To", "")
    elif field_name == "subject":
        return message.get("Subject", "")
    elif field_name == "body":
        # Combine text and html body with size limit to prevent memory issues
        text = payload.get("body_text", "") or ""
        html = payload.get("body_html", "") or ""
        body = f"{text}\n{html}".strip()
        # Truncate to max body size for rules evaluation
        max_size = settings.rules_max_body_size
        if len(body) > max_size:
            logger.debug(
                f"Truncating body from {len(body)} to {max_size} bytes for rules evaluation"
            )
            body = body[:max_size]
        return body
    elif field_name == "has_attachment":
        return "true" if payload.get("has_attachments") else "false"
    elif field_name == "dkim_result":
        return auth_result.dkim_result if auth_result else "none"
    elif field_name == "spf_result":
        return auth_result.spf_result if auth_result else "none"
    elif field_name.startswith("header:"):
        header_name = field_name[7:]  # Remove "header:" prefix
        return message.get(header_name, "")
    else:
        return None


def evaluate_rule(
    rule: Rule,
    message: Message,
    payload: dict,
    auth_result: EmailAuthResult | None = None,
    settings: Settings | None = None,
) -> bool:
    """Evaluate a single rule against an email.

    Args:
        rule: Rule to evaluate
        message: Parsed email message
        payload: Extracted email payload
        auth_result: Email authentication result
        settings: Application settings

    Returns:
        True if the rule matches
    """
    field_value = extract_field_value(rule.field, message, payload, auth_result, settings)

    if field_value is None:
        logger.debug(f"Rule {rule.id}: field '{rule.field}' not found")
        return False

    result = evaluate_condition(
        operator=rule.operator,
        value=field_value,
        pattern=rule.value,
        case_sensitive=rule.case_sensitive,
    )

    if result:
        logger.debug(f"Rule {rule.id} matched: {rule.field} {rule.operator} '{rule.value}'")
    else:
        logger.debug(f"Rule {rule.id} did not match: {rule.field} {rule.operator} '{rule.value}'")

    return result


async def evaluate_rules(
    session: AsyncSession,
    domain: Domain,
    message: Message,
    payload: dict,
    auth_result: EmailAuthResult | None = None,
    settings: Settings | None = None,
) -> RuleEvaluationResult:
    """Evaluate all rules of ``domain`` against an email.

    ``domain`` is the row the caller has already resolved and accepted the
    message for (``lookup_recipient`` on the SMTP path). The engine evaluates
    its rules as they stand and does not re-decide whether the domain is live:
    liveness is decided once per message, by the lookup. Under READ COMMITTED
    a second check here could see a tombstone committed after the lookup, find
    no rulesets, and let a message the lookup already accepted through with
    its drop/quarantine rules skipped - enqueued untagged, delivered the moment
    the domain is restored. A tombstoned domain's rules stay dormant because
    every path that resolves a domain filters ``Domain.live()``, so nothing
    hands a tombstone in here.

    Rules are evaluated in order:
    1. RuleSets are ordered by priority (highest first)
    2. Rules within a RuleSet are ordered by their order field
    3. If stop_on_match is True, stop after first matching rule in a RuleSet

    Args:
        session: Database session
        domain: The domain the message was accepted for
        message: Parsed email message
        payload: Extracted email payload
        auth_result: Email authentication result
        settings: Application settings

    Returns:
        RuleEvaluationResult with all matches and final action
    """
    settings = settings or get_settings()
    result = RuleEvaluationResult()

    # Get all enabled rulesets for this domain, ordered by priority
    stmt = (
        select(RuleSet)
        .options(selectinload(RuleSet.rules))
        .where(
            RuleSet.domain_id == domain.id,
            RuleSet.is_enabled.is_(True),
        )
        .order_by(RuleSet.priority.desc())
    )
    db_result = await session.execute(stmt)
    rulesets = db_result.scalars().all()

    for ruleset in rulesets:
        # Get rules ordered by their order field
        rules = sorted(ruleset.rules, key=lambda r: r.order)

        for rule in rules:
            if evaluate_rule(rule, message, payload, auth_result, settings):
                # Rule matched
                match = RuleMatch(
                    rule_id=rule.id,
                    ruleset_id=ruleset.id,
                    action=rule.action,
                    tags=rule.add_tags or [],
                    webhook_url_override=rule.webhook_url_override,
                    preserve_raw=bool(rule.preserve_raw),
                )
                result.matches.append(match)

                # Add tags
                result.tags.extend(match.tags)

                # Apply action (most severe wins)
                action_priority = {"forward": 0, "tag": 0, "quarantine": 1, "drop": 2}
                if action_priority.get(rule.action, 0) > action_priority.get(result.action, 0):
                    result.action = rule.action

                # Preservation is orthogonal to the action: any match can request it
                if match.preserve_raw:
                    result.preserve_raw = True

                # Store webhook override if specified
                if rule.webhook_url_override:
                    result.webhook_url_override = rule.webhook_url_override

                # Stop processing this ruleset if configured
                if ruleset.stop_on_match:
                    logger.debug(
                        f"RuleSet {ruleset.name}: stopping after match (stop_on_match=True)"
                    )
                    break

    # Deduplicate tags
    result.tags = list(dict.fromkeys(result.tags))

    logger.info(
        f"Rule evaluation complete: {len(result.matches)} matches, "
        f"action={result.action}, tags={result.tags}"
    )

    return result
