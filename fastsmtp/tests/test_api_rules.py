"""Tests for ruleset and rule API endpoints."""

import uuid

import pytest
import pytest_asyncio
from fastsmtp.db.models import Domain, Rule, RuleSet
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


class TestRuleSetsCRUD:
    """Tests for ruleset CRUD operations."""

    @pytest_asyncio.fixture
    async def test_domain(self, test_session: AsyncSession) -> Domain:
        """Create a test domain."""
        domain = Domain(domain_name="rules-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_list_rulesets_empty(
        self, auth_client: AsyncClient, test_domain: Domain
    ):
        """Test listing rulesets when none exist."""
        response = await auth_client.get(
            f"/api/v1/domains/{test_domain.id}/rulesets"
        )
        assert response.status_code == 200
        assert response.json() == []

    @pytest.mark.asyncio
    async def test_create_ruleset(
        self, auth_client: AsyncClient, test_domain: Domain
    ):
        """Test creating a ruleset."""
        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/rulesets",
            json={
                "name": "Test Rules",
                "priority": 10,
                "stop_on_match": True,
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Test Rules"
        assert data["priority"] == 10
        assert data["stop_on_match"] is True
        assert data["is_enabled"] is True

    @pytest.mark.asyncio
    async def test_create_ruleset_duplicate(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test creating duplicate ruleset fails."""
        ruleset = RuleSet(
            domain_id=test_domain.id,
            name="Existing Rules",
            priority=0,
        )
        test_session.add(ruleset)
        await test_session.commit()

        response = await auth_client.post(
            f"/api/v1/domains/{test_domain.id}/rulesets",
            json={"name": "Existing Rules", "priority": 5},
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_rulesets_with_data(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test listing rulesets returns all rulesets."""
        rs1 = RuleSet(domain_id=test_domain.id, name="Rules 1", priority=5)
        rs2 = RuleSet(domain_id=test_domain.id, name="Rules 2", priority=10)
        test_session.add_all([rs1, rs2])
        await test_session.commit()

        response = await auth_client.get(
            f"/api/v1/domains/{test_domain.id}/rulesets"
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        # Should be ordered by priority desc
        assert data[0]["name"] == "Rules 2"
        assert data[1]["name"] == "Rules 1"

    @pytest.mark.asyncio
    async def test_get_ruleset(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test getting a ruleset by ID."""
        ruleset = RuleSet(
            domain_id=test_domain.id,
            name="Get Test",
            priority=0,
        )
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)

        response = await auth_client.get(
            f"/api/v1/domains/{test_domain.id}/rulesets/{ruleset.id}"
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Get Test"
        assert "rules" in data
        assert data["rules"] == []

    @pytest.mark.asyncio
    async def test_get_ruleset_not_found(
        self, auth_client: AsyncClient, test_domain: Domain
    ):
        """Test getting non-existent ruleset returns 404."""
        fake_id = uuid.uuid4()
        response = await auth_client.get(
            f"/api/v1/domains/{test_domain.id}/rulesets/{fake_id}"
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_ruleset(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test updating a ruleset."""
        ruleset = RuleSet(
            domain_id=test_domain.id,
            name="Update Test",
            priority=0,
            is_enabled=True,
        )
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)

        response = await auth_client.put(
            f"/api/v1/domains/{test_domain.id}/rulesets/{ruleset.id}",
            json={"priority": 20, "is_enabled": False},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["priority"] == 20
        assert data["is_enabled"] is False

    @pytest.mark.asyncio
    async def test_delete_ruleset(
        self, auth_client: AsyncClient, test_domain: Domain, test_session: AsyncSession
    ):
        """Test deleting a ruleset."""
        ruleset = RuleSet(
            domain_id=test_domain.id,
            name="Delete Test",
            priority=0,
        )
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)

        response = await auth_client.delete(
            f"/api/v1/domains/{test_domain.id}/rulesets/{ruleset.id}"
        )
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]


class TestRulesCRUD:
    """Tests for rule CRUD operations."""

    @pytest_asyncio.fixture
    async def test_domain_and_ruleset(
        self, test_session: AsyncSession
    ) -> tuple[Domain, RuleSet]:
        """Create a test domain and ruleset."""
        domain = Domain(domain_name="rules-crud-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(
            domain_id=domain.id,
            name="Test Rules",
            priority=0,
        )
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(domain)
        await test_session.refresh(ruleset)
        return domain, ruleset

    @pytest.mark.asyncio
    async def test_create_rule(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test creating a rule."""
        domain, ruleset = test_domain_and_ruleset
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/rules",
            json={
                "field": "from",
                "operator": "contains",
                "value": "@example.com",
                "action": "tag",
                "add_tags": ["external"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["field"] == "from"
        assert data["operator"] == "contains"
        assert data["value"] == "@example.com"
        assert data["action"] == "tag"
        assert data["add_tags"] == ["external"]
        assert data["order"] == 0

    @pytest.mark.asyncio
    async def test_create_rule_with_header_field(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test creating a rule matching a custom header."""
        domain, ruleset = test_domain_and_ruleset
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/rules",
            json={
                "field": "header:X-Priority",
                "operator": "equals",
                "value": "1",
                "action": "tag",
                "add_tags": ["urgent"],
            },
        )
        assert response.status_code == 201
        data = response.json()
        assert data["field"] == "header:X-Priority"

    @pytest.mark.asyncio
    async def test_create_rule_invalid_field(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test creating rule with invalid field fails."""
        domain, ruleset = test_domain_and_ruleset
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/rules",
            json={
                "field": "invalid_field",
                "operator": "equals",
                "value": "test",
                "action": "tag",
            },
        )
        assert response.status_code == 422
        # Pydantic validation error format
        detail = response.json()["detail"]
        assert any("Invalid field" in err["msg"] for err in detail)

    @pytest.mark.asyncio
    async def test_create_rule_invalid_operator(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test creating rule with invalid operator fails."""
        domain, ruleset = test_domain_and_ruleset
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/rules",
            json={
                "field": "from",
                "operator": "invalid_op",
                "value": "test",
                "action": "tag",
            },
        )
        assert response.status_code == 422
        # Pydantic validation error format
        detail = response.json()["detail"]
        assert any("Invalid operator" in err["msg"] for err in detail)

    @pytest.mark.asyncio
    async def test_create_rule_invalid_action(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test creating rule with invalid action fails."""
        domain, ruleset = test_domain_and_ruleset
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/rules",
            json={
                "field": "from",
                "operator": "equals",
                "value": "test",
                "action": "invalid_action",
            },
        )
        assert response.status_code == 422
        # Pydantic validation error format
        detail = response.json()["detail"]
        assert any("Invalid action" in err["msg"] for err in detail)

    @pytest.mark.asyncio
    async def test_create_multiple_rules_order(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test that rules get incremental order numbers."""
        domain, ruleset = test_domain_and_ruleset

        # Create first rule
        r1 = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/rules",
            json={
                "field": "from",
                "operator": "contains",
                "value": "first",
                "action": "tag",
            },
        )
        assert r1.json()["order"] == 0

        # Create second rule
        r2 = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/rules",
            json={
                "field": "from",
                "operator": "contains",
                "value": "second",
                "action": "tag",
            },
        )
        assert r2.json()["order"] == 1

    @pytest.mark.asyncio
    async def test_update_rule(
        self,
        auth_client: AsyncClient,
        test_domain_and_ruleset: tuple[Domain, RuleSet],
        test_session: AsyncSession,
    ):
        """Test updating a rule."""
        domain, ruleset = test_domain_and_ruleset
        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="equals",
            value="old@test.com",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rules/{rule.id}",
            json={
                "value": "new@test.com",
                "action": "drop",
            },
        )
        assert response.status_code == 200, response.json()
        data = response.json()
        assert data["value"] == "new@test.com"
        assert data["action"] == "drop"

    @pytest.mark.asyncio
    async def test_delete_rule(
        self,
        auth_client: AsyncClient,
        test_domain_and_ruleset: tuple[Domain, RuleSet],
        test_session: AsyncSession,
    ):
        """Test deleting a rule."""
        domain, ruleset = test_domain_and_ruleset
        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="equals",
            value="delete@test.com",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        response = await auth_client.delete(
            f"/api/v1/domains/{domain.id}/rules/{rule.id}"
        )
        assert response.status_code == 200
        assert "deleted" in response.json()["message"]


class TestRulesReorder:
    """Tests for rule reordering."""

    @pytest_asyncio.fixture
    async def test_domain_with_rules(
        self, test_session: AsyncSession
    ) -> tuple[Domain, RuleSet, list[Rule]]:
        """Create a test domain with ruleset and rules."""
        domain = Domain(domain_name="reorder-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(
            domain_id=domain.id,
            name="Reorder Rules",
            priority=0,
        )
        test_session.add(ruleset)
        await test_session.flush()

        rules = []
        for i in range(3):
            rule = Rule(
                ruleset_id=ruleset.id,
                order=i,
                field="from",
                operator="contains",
                value=f"rule{i}",
                action="tag",
            )
            test_session.add(rule)
            rules.append(rule)

        await test_session.commit()
        await test_session.refresh(domain)
        await test_session.refresh(ruleset)
        for r in rules:
            await test_session.refresh(r)

        return domain, ruleset, rules

    @pytest.mark.asyncio
    async def test_reorder_rules(
        self,
        auth_client: AsyncClient,
        test_domain_with_rules: tuple[Domain, RuleSet, list[Rule]],
    ):
        """Test reordering rules."""
        domain, ruleset, rules = test_domain_with_rules

        # Reverse the order
        new_order = [rules[2].id, rules[1].id, rules[0].id]
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/reorder",
            json={"rule_ids": [str(rid) for rid in new_order]},
        )
        assert response.status_code == 200
        assert "Reordered 3 rules" in response.json()["message"]

    @pytest.mark.asyncio
    async def test_reorder_missing_rule(
        self,
        auth_client: AsyncClient,
        test_domain_with_rules: tuple[Domain, RuleSet, list[Rule]],
    ):
        """Test reorder fails if rule not in ruleset."""
        domain, ruleset, rules = test_domain_with_rules

        fake_id = uuid.uuid4()
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/reorder",
            json={"rule_ids": [str(fake_id)]},
        )
        assert response.status_code == 400
        assert "not found in this ruleset" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_reorder_incomplete_list(
        self,
        auth_client: AsyncClient,
        test_domain_with_rules: tuple[Domain, RuleSet, list[Rule]],
    ):
        """Test reorder fails if not all rules included."""
        domain, ruleset, rules = test_domain_with_rules

        # Only include 2 of 3 rules
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{ruleset.id}/reorder",
            json={"rule_ids": [str(rules[0].id), str(rules[1].id)]},
        )
        assert response.status_code == 400
        assert "All rules" in response.json()["detail"]


class TestRulesAuth:
    """Tests for rule authentication/authorization."""

    @pytest.mark.asyncio
    async def test_list_rulesets_unauthenticated(self, client: AsyncClient):
        """Test listing rulesets requires authentication."""
        fake_domain_id = uuid.uuid4()
        response = await client.get(f"/api/v1/domains/{fake_domain_id}/rulesets")
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_create_ruleset_unauthenticated(self, client: AsyncClient):
        """Test creating ruleset requires authentication."""
        fake_domain_id = uuid.uuid4()
        response = await client.post(
            f"/api/v1/domains/{fake_domain_id}/rulesets",
            json={"name": "Test", "priority": 0},
        )
        assert response.status_code == 401
