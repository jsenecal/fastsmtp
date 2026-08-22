"""Tests for raw preservation flags on the domain and rule APIs."""

import uuid

import pytest
import pytest_asyncio
from fastapi import FastAPI
from fastsmtp.config import Settings, get_settings
from fastsmtp.db.models import Domain, Rule, RuleSet
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession


@pytest_asyncio.fixture
async def s3_auth_client(app: FastAPI, test_settings: Settings):
    """Authenticated client for an app whose S3 storage is configured."""
    s3_settings = test_settings.model_copy(
        update={
            "s3_bucket": "test-bucket",
            "s3_access_key": test_settings.root_api_key,
            "s3_secret_key": test_settings.root_api_key,
        }
    )
    app.dependency_overrides[get_settings] = lambda: s3_settings

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-API-Key": test_settings.root_api_key.get_secret_value()},
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def ruleset(test_session: AsyncSession) -> RuleSet:
    """Create a domain with an empty ruleset."""
    domain = Domain(domain_name="rules-preserve.example.com", is_enabled=True)
    test_session.add(domain)
    await test_session.flush()
    ruleset = RuleSet(domain_id=domain.id, name="Archive", priority=0, is_enabled=True)
    test_session.add(ruleset)
    await test_session.commit()
    return ruleset


def rule_body(**overrides) -> dict:
    """Build a valid rule creation body."""
    body = {
        "field": "subject",
        "operator": "contains",
        "value": "invoice",
        "action": "tag",
        "add_tags": ["billing"],
    }
    body.update(overrides)
    return body


class TestDomainPreserveRawApi:
    """Tests for preserve_raw_message on the domain API."""

    @pytest.mark.asyncio
    async def test_create_rejects_preservation_without_s3(self, auth_client: AsyncClient):
        """Test enabling preservation without S3 configured is rejected."""
        response = await auth_client.post(
            "/api/v1/domains",
            json={"domain_name": "no-s3.example.com", "preserve_raw_message": True},
        )

        assert response.status_code == 422
        assert "s3_bucket" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_allows_preservation_with_s3(self, s3_auth_client: AsyncClient):
        """Test enabling preservation succeeds when S3 is configured."""
        response = await s3_auth_client.post(
            "/api/v1/domains",
            json={"domain_name": "with-s3.example.com", "preserve_raw_message": True},
        )

        assert response.status_code == 201
        assert response.json()["preserve_raw_message"] is True

    @pytest.mark.asyncio
    async def test_create_allows_disabling_without_s3(self, auth_client: AsyncClient):
        """Test explicitly disabling preservation needs no S3 configuration."""
        response = await auth_client.post(
            "/api/v1/domains",
            json={"domain_name": "off.example.com", "preserve_raw_message": False},
        )

        assert response.status_code == 201
        assert response.json()["preserve_raw_message"] is False

    @pytest.mark.asyncio
    async def test_create_defaults_to_inherit(self, auth_client: AsyncClient):
        """Test an unset flag leaves the domain inheriting the global default."""
        response = await auth_client.post(
            "/api/v1/domains",
            json={"domain_name": "inherit.example.com"},
        )

        assert response.status_code == 201
        assert response.json()["preserve_raw_message"] is None

    @pytest.mark.asyncio
    async def test_update_rejects_preservation_without_s3(
        self, auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test turning preservation on via update is rejected without S3."""
        domain = Domain(domain_name="update-no-s3.example.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        response = await auth_client.put(
            f"/api/v1/domains/{domain.id}",
            json={"preserve_raw_message": True},
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_update_allows_preservation_with_s3(
        self, s3_auth_client: AsyncClient, test_session: AsyncSession
    ):
        """Test turning preservation on via update succeeds with S3 configured."""
        domain = Domain(domain_name="update-s3.example.com", is_enabled=True)
        test_session.add(domain)
        await test_session.commit()

        response = await s3_auth_client.put(
            f"/api/v1/domains/{domain.id}",
            json={"preserve_raw_message": True},
        )

        assert response.status_code == 200
        assert response.json()["preserve_raw_message"] is True


class TestRulePreserveRawApi:
    """Tests for preserve_raw on the rule API."""

    @pytest.mark.asyncio
    async def test_create_rejects_preservation_without_s3(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        """Test a preserving rule is rejected without S3 configured."""
        response = await auth_client.post(
            f"/api/v1/domains/{ruleset.domain_id}/rulesets/{ruleset.id}/rules",
            json=rule_body(preserve_raw=True),
        )

        assert response.status_code == 422
        assert "s3_bucket" in response.json()["detail"]

    @pytest.mark.asyncio
    async def test_create_allows_preservation_with_s3(
        self, s3_auth_client: AsyncClient, ruleset: RuleSet
    ):
        """Test a preserving rule is accepted when S3 is configured."""
        response = await s3_auth_client.post(
            f"/api/v1/domains/{ruleset.domain_id}/rulesets/{ruleset.id}/rules",
            json=rule_body(preserve_raw=True),
        )

        assert response.status_code == 201
        assert response.json()["preserve_raw"] is True

    @pytest.mark.asyncio
    async def test_create_defaults_to_no_preservation(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        """Test rules do not preserve by default."""
        response = await auth_client.post(
            f"/api/v1/domains/{ruleset.domain_id}/rulesets/{ruleset.id}/rules",
            json=rule_body(),
        )

        assert response.status_code == 201
        assert response.json()["preserve_raw"] is False

    @pytest.mark.asyncio
    async def test_update_rejects_preservation_without_s3(
        self, auth_client: AsyncClient, ruleset: RuleSet, test_session: AsyncSession
    ):
        """Test turning preservation on via update is rejected without S3."""
        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="subject",
            operator="contains",
            value="invoice",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()

        response = await auth_client.put(
            f"/api/v1/domains/{ruleset.domain_id}/rules/{rule.id}",
            json={"preserve_raw": True},
        )

        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_update_allows_preservation_with_s3(
        self, s3_auth_client: AsyncClient, ruleset: RuleSet, test_session: AsyncSession
    ):
        """Test turning preservation on via update succeeds with S3 configured."""
        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="subject",
            operator="contains",
            value="invoice",
            action="tag",
        )
        test_session.add(rule)
        await test_session.commit()

        response = await s3_auth_client.put(
            f"/api/v1/domains/{ruleset.domain_id}/rules/{rule.id}",
            json={"preserve_raw": True},
        )

        assert response.status_code == 200
        assert response.json()["preserve_raw"] is True

    @pytest.mark.asyncio
    async def test_update_allows_disabling_without_s3(
        self, auth_client: AsyncClient, ruleset: RuleSet, test_session: AsyncSession
    ):
        """Test turning preservation off never requires S3 configuration."""
        rule = Rule(
            ruleset_id=ruleset.id,
            order=0,
            field="subject",
            operator="contains",
            value="invoice",
            action="tag",
            preserve_raw=True,
        )
        test_session.add(rule)
        await test_session.commit()

        response = await auth_client.put(
            f"/api/v1/domains/{ruleset.domain_id}/rules/{rule.id}",
            json={"preserve_raw": False},
        )

        assert response.status_code == 200
        assert response.json()["preserve_raw"] is False

    @pytest.mark.asyncio
    async def test_update_missing_rule_still_404(self, auth_client: AsyncClient, ruleset: RuleSet):
        """Test the S3 check does not mask a missing rule."""
        response = await auth_client.put(
            f"/api/v1/domains/{ruleset.domain_id}/rules/{uuid.uuid4()}",
            json={"preserve_raw": True},
        )

        assert response.status_code == 404
