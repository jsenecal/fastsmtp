"""Tests for health and operations endpoints."""

import pytest
from fastsmtp import __version__
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    """Test the health check endpoint."""
    response = await client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["version"] == __version__
    assert "instance_id" in data


@pytest.mark.asyncio
async def test_health_unauthenticated(client: AsyncClient):
    """Health endpoint should work without authentication."""
    response = await client.get("/api/health")
    assert response.status_code == 200
