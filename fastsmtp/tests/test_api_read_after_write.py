"""Read-your-own-write guarantees for the HTTP API.

Committing in a ``yield`` dependency's teardown loses this guarantee: teardown
starts before the response is sent, so the moment it awaits the commit the event
loop flushes the response. A client that immediately reads what it just wrote can
reach a fresh session before the commit lands and get a 404.

The window is the commit's own duration - about 1ms locally, which is why this
surfaced only as a rare CI flake. These tests make it deterministic by slowing
the commit to 100ms. Loss begins around 5ms, which is an unremarkable latency for
a loaded database, a synchronously replicated one, or an fsync spike.
"""

import asyncio
from collections.abc import Callable

import httpx
import pytest
from fastapi import FastAPI
from fastsmtp.config import Settings
from sqlalchemy.ext.asyncio import AsyncSession

SLOW_COMMIT = 0.100


@pytest.fixture
def slow_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Slow every commit, widening the race window to a certain loss."""
    original = AsyncSession.commit

    async def commit(self: AsyncSession) -> None:
        await asyncio.sleep(SLOW_COMMIT)
        await original(self)

    monkeypatch.setattr(AsyncSession, "commit", commit)


@pytest.fixture
def api_url(server_url: str, slow_commit: None) -> str:
    """Base API URL on the shared TCP server, with commits slowed."""
    return f"{server_url}/api/v1"


@pytest.fixture
def client_factory(api_url: str, test_settings: Settings) -> Callable[[], httpx.Client]:
    """Build sync httpx clients pointed at the running server."""

    def factory() -> httpx.Client:
        return httpx.Client(
            base_url=api_url,
            headers={"X-API-Key": test_settings.root_api_key.get_secret_value()},
            timeout=10.0,
        )

    return factory


async def test_created_resource_is_readable_immediately(
    client_factory: Callable[[], httpx.Client],
    run_blocking,
) -> None:
    """A resource must be readable on the very next request that creates it."""

    def body() -> httpx.Response:
        with client_factory() as client:
            domain = client.post("/domains", json={"domain_name": "raw-read.test"})
            assert domain.status_code == 201, domain.text
            domain_id = domain.json()["id"]

            created = client.post(
                f"/domains/{domain_id}/recipients",
                json={"webhook_url": "https://hook.test/inbox", "local_part": "support"},
            )
            assert created.status_code == 201, created.text

            return client.get(f"/domains/{domain_id}/recipients/{created.json()['id']}")

    response = await run_blocking(body)

    assert response.status_code == 200, (
        f"read-your-own-write lost: {response.status_code} {response.text}"
    )
    assert response.json()["local_part"] == "support"


async def test_created_parent_is_visible_to_the_next_write(
    client_factory: Callable[[], httpx.Client],
    run_blocking,
) -> None:
    """A nested create must see the parent created by the previous request.

    The parent is created by a *previous request*, so its commit must have landed
    before this one begins. An uncommitted parent fails the write itself, not just
    a read: get_domain_with_access cannot find it.
    """

    def body() -> httpx.Response:
        with client_factory() as client:
            domain = client.post("/domains", json={"domain_name": "raw-parent.test"})
            assert domain.status_code == 201, domain.text

            return client.post(
                f"/domains/{domain.json()['id']}/recipients",
                json={"webhook_url": "https://hook.test/inbox", "local_part": "a"},
            )

    response = await run_blocking(body)

    assert response.status_code == 201, (
        f"nested create could not see its parent: {response.status_code} {response.text}"
    )


async def test_read_after_write_holds_on_a_separate_connection(
    client_factory: Callable[[], httpx.Client],
    run_blocking,
) -> None:
    """The guarantee must not depend on reusing the writer's connection.

    Behind a load balancer the follow-up read routinely lands on a different
    connection, so serialisation on one keep-alive socket cannot be relied on.
    """

    def body() -> httpx.Response:
        with client_factory() as writer:
            domain_id = writer.post("/domains", json={"domain_name": "raw-separate.test"}).json()[
                "id"
            ]
            created = writer.post(
                f"/domains/{domain_id}/recipients",
                json={"webhook_url": "https://hook.test/inbox", "local_part": "a"},
            )
            assert created.status_code == 201, created.text

        with client_factory() as reader:
            return reader.get(f"/domains/{domain_id}/recipients/{created.json()['id']}")

    response = await run_blocking(body)

    assert response.status_code == 200, (
        f"read-your-own-write lost across connections: {response.status_code} {response.text}"
    )


class TestSessionRollback:
    """The middleware owns rollback as well as commit."""

    @pytest.fixture
    def rollback_app(self, test_settings: Settings, test_engine) -> FastAPI:
        """An app with routes that write and then fail, in two different ways."""
        from fastapi import Depends, HTTPException
        from fastsmtp.db.models import Domain
        from fastsmtp.db.session import get_session
        from fastsmtp.main import create_app
        from sqlalchemy.ext.asyncio import async_sessionmaker

        application = create_app(test_settings)
        application.state.session_factory = async_sessionmaker(
            test_engine, class_=AsyncSession, expire_on_commit=False
        )

        @application.post("/probe/http-error")
        async def http_error(session: AsyncSession = Depends(get_session)) -> None:
            session.add(Domain(domain_name="rollback-http.test"))
            await session.flush()
            raise HTTPException(status_code=400, detail="nope")

        @application.post("/probe/crash")
        async def crash(session: AsyncSession = Depends(get_session)) -> None:
            session.add(Domain(domain_name="rollback-crash.test"))
            await session.flush()
            raise RuntimeError("boom")

        return application

    async def _domain_exists(self, test_engine, name: str) -> bool:
        from fastsmtp.db.models import Domain
        from sqlalchemy import select
        from sqlalchemy.ext.asyncio import async_sessionmaker

        factory = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)
        async with factory() as session:
            result = await session.execute(select(Domain).where(Domain.domain_name == name))
            return result.scalar_one_or_none() is not None

    async def test_http_error_response_discards_partial_writes(
        self, rollback_app: FastAPI, test_engine, test_settings: Settings, run_blocking
    ) -> None:
        """A 4xx response must not persist writes the handler made first."""
        transport = httpx.ASGITransport(app=rollback_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/probe/http-error")

        assert response.status_code == 400
        assert not await self._domain_exists(test_engine, "rollback-http.test")

    async def test_unhandled_exception_discards_partial_writes(
        self, rollback_app: FastAPI, test_engine, run_blocking
    ) -> None:
        """An unhandled exception must not persist writes the handler made first."""
        transport = httpx.ASGITransport(app=rollback_app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/probe/crash")

        assert response.status_code == 500
        assert not await self._domain_exists(test_engine, "rollback-crash.test")
