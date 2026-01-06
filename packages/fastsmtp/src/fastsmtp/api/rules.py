"""RuleSet and Rule management API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from fastsmtp.auth import Auth, get_domain_with_access
from fastsmtp.db.models import Rule, RuleSet
from fastsmtp.db.session import get_session
from fastsmtp.schemas.rule import (
    RULE_ACTIONS,
    RULE_FIELDS,
    RULE_HEADER_PREFIX,
    RULE_OPERATORS,
    RuleCreate,
    RuleReorderRequest,
    RuleResponse,
    RuleSetCreate,
    RuleSetResponse,
    RuleSetUpdate,
    RuleSetWithRulesResponse,
    RuleUpdate,
)

router = APIRouter(tags=["rules"])


def validate_rule_field(field: str) -> None:
    """Validate rule field name."""
    if field in RULE_FIELDS:
        return
    if field.startswith(RULE_HEADER_PREFIX):
        return
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Invalid field '{field}'. Valid fields: {', '.join(RULE_FIELDS)}, "
        f"or {RULE_HEADER_PREFIX}X-Header-Name",
    )


def validate_rule_operator(operator: str) -> None:
    """Validate rule operator."""
    if operator not in RULE_OPERATORS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid operator '{operator}'. Valid operators: {', '.join(RULE_OPERATORS)}",
        )


def validate_rule_action(action: str) -> None:
    """Validate rule action."""
    if action not in RULE_ACTIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action '{action}'. Valid actions: {', '.join(RULE_ACTIONS)}",
        )


# RuleSet endpoints


@router.get("/domains/{domain_id}/rulesets", response_model=list[RuleSetResponse])
async def list_rulesets(
    domain_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> list[RuleSetResponse]:
    """List all rulesets for a domain."""
    await get_domain_with_access(domain_id, auth, session, required_role="member")
    auth.require_scope("rules:read")

    stmt = (
        select(RuleSet)
        .where(RuleSet.domain_id == domain_id)
        .order_by(RuleSet.priority.desc(), RuleSet.name)
    )
    result = await session.execute(stmt)
    rulesets = result.scalars().all()
    return [RuleSetResponse.model_validate(rs) for rs in rulesets]


@router.post(
    "/domains/{domain_id}/rulesets",
    response_model=RuleSetResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_ruleset(
    domain_id: uuid.UUID,
    data: RuleSetCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RuleSetResponse:
    """Create a new ruleset for a domain."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("rules:write")

    # Check for duplicate name
    stmt = select(RuleSet).where(
        RuleSet.domain_id == domain_id,
        RuleSet.name == data.name,
    )
    result = await session.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Ruleset '{data.name}' already exists for this domain",
        )

    ruleset = RuleSet(
        domain_id=domain_id,
        name=data.name,
        priority=data.priority,
        stop_on_match=data.stop_on_match,
    )
    session.add(ruleset)
    await session.flush()
    await session.refresh(ruleset)

    return RuleSetResponse.model_validate(ruleset)


@router.get(
    "/domains/{domain_id}/rulesets/{ruleset_id}",
    response_model=RuleSetWithRulesResponse,
)
async def get_ruleset(
    domain_id: uuid.UUID,
    ruleset_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RuleSetWithRulesResponse:
    """Get a ruleset with its rules."""
    await get_domain_with_access(domain_id, auth, session, required_role="member")
    auth.require_scope("rules:read")

    stmt = (
        select(RuleSet)
        .options(selectinload(RuleSet.rules))
        .where(
            RuleSet.id == ruleset_id,
            RuleSet.domain_id == domain_id,
        )
    )
    result = await session.execute(stmt)
    ruleset = result.scalar_one_or_none()

    if not ruleset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ruleset not found",
        )

    response = RuleSetWithRulesResponse.model_validate(ruleset)
    response.rules = [RuleResponse.model_validate(r) for r in ruleset.rules]
    return response


@router.put("/domains/{domain_id}/rulesets/{ruleset_id}", response_model=RuleSetResponse)
async def update_ruleset(
    domain_id: uuid.UUID,
    ruleset_id: uuid.UUID,
    data: RuleSetUpdate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RuleSetResponse:
    """Update a ruleset."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("rules:write")

    stmt = select(RuleSet).where(
        RuleSet.id == ruleset_id,
        RuleSet.domain_id == domain_id,
    )
    result = await session.execute(stmt)
    ruleset = result.scalar_one_or_none()

    if not ruleset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ruleset not found",
        )

    update_data = data.model_dump(exclude_unset=True)

    # Check for duplicate name if changing
    if "name" in update_data and update_data["name"] != ruleset.name:
        check_stmt = select(RuleSet).where(
            RuleSet.domain_id == domain_id,
            RuleSet.id != ruleset_id,
            RuleSet.name == update_data["name"],
        )
        check_result = await session.execute(check_stmt)
        if check_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ruleset '{update_data['name']}' already exists for this domain",
            )

    for field, value in update_data.items():
        setattr(ruleset, field, value)

    await session.flush()
    await session.refresh(ruleset)

    return RuleSetResponse.model_validate(ruleset)


@router.delete("/domains/{domain_id}/rulesets/{ruleset_id}")
async def delete_ruleset(
    domain_id: uuid.UUID,
    ruleset_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Delete a ruleset and all its rules."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("rules:write")

    stmt = select(RuleSet).where(
        RuleSet.id == ruleset_id,
        RuleSet.domain_id == domain_id,
    )
    result = await session.execute(stmt)
    ruleset = result.scalar_one_or_none()

    if not ruleset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ruleset not found",
        )

    name = ruleset.name
    await session.delete(ruleset)
    return {"message": f"Ruleset '{name}' deleted"}


# Rule endpoints


@router.post(
    "/domains/{domain_id}/rulesets/{ruleset_id}/rules",
    response_model=RuleResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule(
    domain_id: uuid.UUID,
    ruleset_id: uuid.UUID,
    data: RuleCreate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RuleResponse:
    """Add a rule to a ruleset."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("rules:write")

    # Validate rule fields
    validate_rule_field(data.field)
    validate_rule_operator(data.operator)
    validate_rule_action(data.action)

    # Verify ruleset exists
    stmt = select(RuleSet).where(
        RuleSet.id == ruleset_id,
        RuleSet.domain_id == domain_id,
    )
    result = await session.execute(stmt)
    if not result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ruleset not found",
        )

    # Get next order number
    order_stmt = select(func.coalesce(func.max(Rule.order), -1) + 1).where(
        Rule.ruleset_id == ruleset_id
    )
    order_result = await session.execute(order_stmt)
    next_order = order_result.scalar()

    rule = Rule(
        ruleset_id=ruleset_id,
        order=next_order,
        field=data.field,
        operator=data.operator,
        value=data.value,
        case_sensitive=data.case_sensitive,
        action=data.action,
        webhook_url_override=str(data.webhook_url_override) if data.webhook_url_override else None,
        add_tags=data.add_tags,
    )
    session.add(rule)
    await session.flush()
    await session.refresh(rule)

    return RuleResponse.model_validate(rule)


@router.put("/domains/{domain_id}/rules/{rule_id}", response_model=RuleResponse)
async def update_rule(
    domain_id: uuid.UUID,
    rule_id: uuid.UUID,
    data: RuleUpdate,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> RuleResponse:
    """Update a rule."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("rules:write")

    # Get rule and verify it belongs to a ruleset in this domain
    stmt = (
        select(Rule)
        .join(RuleSet)
        .where(
            Rule.id == rule_id,
            RuleSet.domain_id == domain_id,
        )
    )
    result = await session.execute(stmt)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    update_data = data.model_dump(exclude_unset=True)

    # Validate if changing field/operator/action
    if "field" in update_data:
        validate_rule_field(update_data["field"])
    if "operator" in update_data:
        validate_rule_operator(update_data["operator"])
    if "action" in update_data:
        validate_rule_action(update_data["action"])

    # Handle webhook_url conversion
    if "webhook_url_override" in update_data and update_data["webhook_url_override"]:
        update_data["webhook_url_override"] = str(update_data["webhook_url_override"])

    for field, value in update_data.items():
        setattr(rule, field, value)

    await session.flush()
    await session.refresh(rule)

    return RuleResponse.model_validate(rule)


@router.delete("/domains/{domain_id}/rules/{rule_id}")
async def delete_rule(
    domain_id: uuid.UUID,
    rule_id: uuid.UUID,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Delete a rule."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("rules:write")

    stmt = (
        select(Rule)
        .join(RuleSet)
        .where(
            Rule.id == rule_id,
            RuleSet.domain_id == domain_id,
        )
    )
    result = await session.execute(stmt)
    rule = result.scalar_one_or_none()

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rule not found",
        )

    await session.delete(rule)
    return {"message": "Rule deleted"}


@router.post("/domains/{domain_id}/rulesets/{ruleset_id}/reorder")
async def reorder_rules(
    domain_id: uuid.UUID,
    ruleset_id: uuid.UUID,
    data: RuleReorderRequest,
    auth: Auth,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    """Reorder rules within a ruleset."""
    await get_domain_with_access(domain_id, auth, session, required_role="admin")
    auth.require_scope("rules:write")

    # Verify ruleset exists
    ruleset_stmt = select(RuleSet).where(
        RuleSet.id == ruleset_id,
        RuleSet.domain_id == domain_id,
    )
    ruleset_result = await session.execute(ruleset_stmt)
    if not ruleset_result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Ruleset not found",
        )

    # Get all rules in this ruleset
    rules_stmt = select(Rule).where(Rule.ruleset_id == ruleset_id)
    rules_result = await session.execute(rules_stmt)
    rules = {r.id: r for r in rules_result.scalars().all()}

    # Validate that all rule_ids belong to this ruleset
    for rule_id in data.rule_ids:
        if rule_id not in rules:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Rule {rule_id} not found in this ruleset",
            )

    # Check all rules are included
    if set(data.rule_ids) != set(rules.keys()):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="All rules in the ruleset must be included in the reorder request",
        )

    # Update order
    for order, rule_id in enumerate(data.rule_ids):
        rules[rule_id].order = order

    await session.flush()
    return {"message": f"Reordered {len(data.rule_ids)} rules"}
