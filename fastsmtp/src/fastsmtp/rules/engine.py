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
from fastsmtp.rules.conditions import RegexTimeoutError, evaluate_condition
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


@dataclass
class RuleEvaluationResult:
    """Result of evaluating all rules for an email."""

    matches: list[RuleMatch] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    action: str = "forward"  # forward, drop, quarantine
    webhook_url_override: str | None = None

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
        True if the rule matches. Also returns True if regex evaluation times out
        (fail-safe: treat timeout as a match to prevent rule bypass).
    """
    field_value = extract_field_value(rule.field, message, payload, auth_result, settings)

    if field_value is None:
        logger.debug(f"Rule {rule.id}: field '{rule.field}' not found")
        return False

    try:
        result = evaluate_condition(
            operator=rule.operator,
            value=field_value,
            pattern=rule.value,
            case_sensitive=rule.case_sensitive,
        )
    except RegexTimeoutError:
        # Fail-safe: treat regex timeout as a match to prevent rule bypass.
        # If a rule was designed to block spam/malware and it times out,
        # we should assume it would have matched rather than let the email through.
        logger.warning(
            f"Rule {rule.id} regex timed out - treating as match (fail-safe). "
            f"Field: {rule.field}, Pattern: {rule.value[:50]}..."
        )
        return True

    if result:
        logger.debug(f"Rule {rule.id} matched: {rule.field} {rule.operator} '{rule.value}'")
    else:
        logger.debug(f"Rule {rule.id} did not match: {rule.field} {rule.operator} '{rule.value}'")

    return result


async def evaluate_rules(
    session: AsyncSession,
    domain_id: uuid.UUID,
    message: Message,
    payload: dict,
    auth_result: EmailAuthResult | None = None,
    settings: Settings | None = None,
) -> RuleEvaluationResult:
    """Evaluate all rules for a domain against an email.

    Rules are evaluated in order:
    1. RuleSets are ordered by priority (highest first)
    2. Rules within a RuleSet are ordered by their order field
    3. If stop_on_match is True, stop after first matching rule in a RuleSet

    Args:
        session: Database session
        domain_id: Domain ID
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
            RuleSet.domain_id == domain_id,
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
                )
                result.matches.append(match)

                # Add tags
                result.tags.extend(match.tags)

                # Apply action (most severe wins)
                action_priority = {"forward": 0, "tag": 0, "quarantine": 1, "drop": 2}
                if action_priority.get(rule.action, 0) > action_priority.get(result.action, 0):
                    result.action = rule.action

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


async def get_domain_auth_settings(
    session: AsyncSession,
    domain_id: uuid.UUID,
) -> tuple[bool | None, bool | None, bool | None, bool | None]:
    """Get authentication settings for a domain.

    Returns domain-specific settings if set, otherwise falls back to None
    (caller should use global settings).

    Args:
        session: Database session
        domain_id: Domain ID

    Returns:
        Tuple of (verify_dkim, verify_spf, reject_dkim_fail, reject_spf_fail)
        Values are None if not overridden at domain level
    """
    stmt = select(Domain).where(Domain.id == domain_id)
    result = await session.execute(stmt)
    domain = result.scalar_one_or_none()

    if not domain:
        return None, None, None, None

    return (
        domain.verify_dkim,
        domain.verify_spf,
        domain.reject_dkim_fail,
        domain.reject_spf_fail,
    )
