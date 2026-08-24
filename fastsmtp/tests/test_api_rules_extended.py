"""Extended tests for rules API endpoints to improve coverage."""

import uuid

import pytest
import pytest_asyncio
from fastsmtp.db.models import Domain, Rule, RuleSet
from httpx import AsyncClient
from sqlalchemy import false
from sqlalchemy.ext.asyncio import AsyncSession


class TestRuleSetUpdateExtended:
    """Extended tests for ruleset update operations."""

    @pytest_asyncio.fixture
    async def test_domain_with_rulesets(
        self, test_session: AsyncSession
    ) -> tuple[Domain, RuleSet, RuleSet]:
        """Create a domain with two rulesets."""
        domain = Domain(domain_name="ruleset-update-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        rs1 = RuleSet(domain_id=domain.id, name="Ruleset 1", priority=10)
        rs2 = RuleSet(domain_id=domain.id, name="Ruleset 2", priority=5)
        test_session.add_all([rs1, rs2])
        await test_session.commit()
        await test_session.refresh(domain)
        await test_session.refresh(rs1)
        await test_session.refresh(rs2)
        return domain, rs1, rs2

    @pytest.mark.asyncio
    async def test_update_ruleset_duplicate_name(
        self,
        auth_client: AsyncClient,
        test_domain_with_rulesets: tuple[Domain, RuleSet, RuleSet],
    ):
        """Test updating ruleset with duplicate name fails."""
        domain, rs1, rs2 = test_domain_with_rulesets

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rulesets/{rs2.id}",
            json={"name": "Ruleset 1"},  # Same as rs1
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_update_ruleset_not_found(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test updating non-existent ruleset returns 404."""
        domain = Domain(domain_name="ruleset-notfound.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        fake_id = uuid.uuid4()
        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rulesets/{fake_id}",
            json={"name": "New Name"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_ruleset_not_found(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test deleting non-existent ruleset returns 404."""
        domain = Domain(domain_name="ruleset-delete-notfound.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        fake_id = uuid.uuid4()
        response = await auth_client.delete(f"/api/v1/domains/{domain.id}/rulesets/{fake_id}")
        assert response.status_code == 404


class TestRuleUpdateExtended:
    """Extended tests for rule update operations."""

    @pytest_asyncio.fixture
    async def test_domain_and_ruleset(self, test_session: AsyncSession) -> tuple[Domain, RuleSet]:
        """Create a domain and ruleset."""
        domain = Domain(domain_name="rule-update-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Test Rules", priority=0)
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(domain)
        await test_session.refresh(ruleset)
        return domain, ruleset

    @pytest.mark.asyncio
    async def test_update_rule_field_validation(
        self,
        auth_client: AsyncClient,
        test_domain_and_ruleset: tuple[Domain, RuleSet],
        test_session: AsyncSession,
    ):
        """Test updating rule with invalid field fails."""
        domain, ruleset = test_domain_and_ruleset

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="equals",
            value="test@example.com",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rules/{rule.id}",
            json={"field": "invalid_field"},
        )
        assert response.status_code == 422
        # Pydantic validation error format
        detail = response.json()["detail"]
        assert any("Invalid field" in err["msg"] for err in detail)

    @pytest.mark.asyncio
    async def test_update_rule_operator_validation(
        self,
        auth_client: AsyncClient,
        test_domain_and_ruleset: tuple[Domain, RuleSet],
        test_session: AsyncSession,
    ):
        """Test updating rule with invalid operator fails."""
        domain, ruleset = test_domain_and_ruleset

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="equals",
            value="test@example.com",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rules/{rule.id}",
            json={"operator": "invalid_operator"},
        )
        assert response.status_code == 422
        # Pydantic validation error format
        detail = response.json()["detail"]
        assert any("Invalid operator" in err["msg"] for err in detail)

    @pytest.mark.asyncio
    async def test_update_rule_action_validation(
        self,
        auth_client: AsyncClient,
        test_domain_and_ruleset: tuple[Domain, RuleSet],
        test_session: AsyncSession,
    ):
        """Test updating rule with invalid action fails."""
        domain, ruleset = test_domain_and_ruleset

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="from",
            operator="equals",
            value="test@example.com",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rules/{rule.id}",
            json={"action": "invalid_action"},
        )
        assert response.status_code == 422
        # Pydantic validation error format
        detail = response.json()["detail"]
        assert any("Invalid action" in err["msg"] for err in detail)

    @pytest.mark.asyncio
    async def test_update_rule_not_found(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test updating non-existent rule returns 404."""
        domain, _ = test_domain_and_ruleset
        fake_id = uuid.uuid4()

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rules/{fake_id}",
            json={"value": "new_value"},
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_rule_not_found(
        self, auth_client: AsyncClient, test_domain_and_ruleset: tuple[Domain, RuleSet]
    ):
        """Test deleting non-existent rule returns 404."""
        domain, _ = test_domain_and_ruleset
        fake_id = uuid.uuid4()

        response = await auth_client.delete(f"/api/v1/domains/{domain.id}/rules/{fake_id}")
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_update_rule_value(
        self,
        auth_client: AsyncClient,
        test_domain_and_ruleset: tuple[Domain, RuleSet],
        test_session: AsyncSession,
    ):
        """Test updating rule value."""
        domain, ruleset = test_domain_and_ruleset

        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="subject",
            operator="contains",
            value="urgent",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()
        await test_session.refresh(rule)

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rules/{rule.id}",
            json={"value": "critical"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["value"] == "critical"

    @pytest.mark.asyncio
    async def test_create_rule_for_nonexistent_ruleset(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test creating rule for non-existent ruleset."""
        domain = Domain(domain_name="rule-create-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        fake_ruleset_id = uuid.uuid4()
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{fake_ruleset_id}/rules",
            json={
                "field": "from",
                "operator": "equals",
                "value": "test@example.com",
                "action": "tag",
            },
        )
        assert response.status_code == 404


class TestRulesReorderExtended:
    """Extended tests for rule reordering."""

    @pytest_asyncio.fixture
    async def test_domain_with_rules(
        self, test_session: AsyncSession
    ) -> tuple[Domain, RuleSet, list[Rule]]:
        """Create a domain with ruleset and rules."""
        domain = Domain(domain_name="reorder-extended-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        ruleset = RuleSet(domain_id=domain.id, name="Reorder Rules", priority=0)
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
    async def test_reorder_nonexistent_ruleset(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test reordering rules in non-existent ruleset."""
        domain = Domain(domain_name="reorder-notfound.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()
        await test_session.refresh(domain)

        fake_id = uuid.uuid4()
        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets/{fake_id}/reorder",
            json={"rule_ids": [str(uuid.uuid4())]},
        )
        assert response.status_code == 404


class TestRuleSetConflictRace:
    """The loser of a concurrent duplicate ruleset write must get the pre-check's 409.

    create_ruleset and update_ruleset are check-then-flush, so two concurrent
    requests can both pass the duplicate check; the loser then hits
    uq_ruleset_name at flush time. The loser is simulated deterministically
    by patching the pre-check filter to match nothing, which is exactly what
    its stale read saw.
    """

    @pytest.fixture
    def losing_precheck(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Make the duplicate pre-check see no conflict, as the race's loser does."""
        import fastsmtp.api.rules as rules_api

        monkeypatch.setattr(rules_api, "_conflicting_ruleset_name", lambda domain_id, name: false())

    @pytest_asyncio.fixture
    async def raced_domain(self, test_session: AsyncSession) -> tuple[Domain, RuleSet]:
        """A domain holding rulesets 'keep' and 'target'; returns (domain, target)."""
        domain = Domain(domain_name="ruleset-race.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        target = RuleSet(domain_id=domain.id, name="target")
        test_session.add_all([RuleSet(domain_id=domain.id, name="keep"), target])
        await test_session.commit()
        await test_session.refresh(domain)
        await test_session.refresh(target)
        return domain, target

    @pytest.mark.asyncio
    async def test_raced_duplicate_create_returns_409(
        self,
        auth_client: AsyncClient,
        raced_domain: tuple[Domain, RuleSet],
        losing_precheck: None,
    ):
        """A create that loses the race gets 409, not a 500 from the constraint."""
        domain, _ = raced_domain

        response = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets", json={"name": "keep"}
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]

        # The translated conflict must leave the app serviceable
        fresh = await auth_client.post(
            f"/api/v1/domains/{domain.id}/rulesets", json={"name": "unraced"}
        )
        assert fresh.status_code == 201

    @pytest.mark.asyncio
    async def test_raced_duplicate_update_returns_409(
        self,
        auth_client: AsyncClient,
        raced_domain: tuple[Domain, RuleSet],
        losing_precheck: None,
    ):
        """An update that loses the race gets 409, not a 500 from the constraint."""
        domain, target = raced_domain

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}/rulesets/{target.id}", json={"name": "keep"}
        )
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]
