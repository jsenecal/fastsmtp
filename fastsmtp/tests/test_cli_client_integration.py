"""Integration tests driving the fsmtp CLI client against the real FastAPI app.

Regression tests for GitHub issues #39 (client used /api/... paths while the
server mounts everything under /api/v1) and #40 (client sent an
"Authorization: Bearer" header while the server authenticates via "X-API-Key").

The real application is served over TCP with uvicorn in a background thread so
the synchronous httpx client used by fastsmtp-cli can talk to it end-to-end.
"""

import threading

import anyio
import pytest
import uvicorn
from fastapi import FastAPI
from fastsmtp.config import Settings
from fastsmtp_cli.client import FastSMTPClient
from fastsmtp_cli.config import Profile


@pytest.fixture
async def server_url(app: FastAPI):
    """Serve the test app over TCP on an ephemeral port and yield its URL."""
    config = uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    while not server.started:
        if not thread.is_alive():  # pragma: no cover - startup failure
            raise RuntimeError("uvicorn server failed to start")
        await anyio.sleep(0.02)

    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def cli_client(server_url: str, test_settings: Settings) -> FastSMTPClient:
    """CLI client configured against the running test server with the root key."""
    profile = Profile(
        url=server_url,
        api_key=test_settings.root_api_key.get_secret_value(),
        timeout=10.0,
        verify_ssl=False,
    )
    return FastSMTPClient(profile=profile)


async def test_cli_client_health_reaches_server(cli_client: FastSMTPClient) -> None:
    """The client's health() must hit the server's mounted /api/v1/health route."""
    with cli_client as client:
        result = client.health()

    assert result["status"] == "ok"


async def test_cli_client_authenticated_whoami(cli_client: FastSMTPClient) -> None:
    """An authenticated whoami must reach the server and be accepted.

    Fails with a 404 if the client uses the wrong path prefix (issue #39) and
    with a 401 if it sends the wrong auth header (issue #40).
    """
    with cli_client as client:
        result = client.whoami()

    assert result["is_root"] is True
    assert result["user"]["username"] == "root"
