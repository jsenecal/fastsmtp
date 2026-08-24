"""Integration tests driving the fsmtp CLI client against the real FastAPI app.

Regression tests for GitHub issues #39 (client used /api/... paths while the
server mounts everything under /api/v1), #40 (client sent an
"Authorization: Bearer" header while the server authenticates via "X-API-Key")
and #46 (13 client calls targeted routes the server does not serve, and payloads
carried fields its schemas do not define).

The real application is served over TCP by uvicorn inside the test's own event
loop, so request handlers share the loop the test-database engine was created
on. The synchronous httpx client used by fastsmtp-cli would block that loop, so
each test body runs on a worker thread via ``anyio.to_thread.run_sync``.
"""

import pytest
from fastsmtp.config import Settings
from fastsmtp_cli.client import APIError, FastSMTPClient
from fastsmtp_cli.config import Profile


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


async def test_cli_client_health_reaches_server(cli_client: FastSMTPClient, run_blocking) -> None:
    """The client's health() must hit the server's mounted /api/v1/health route."""

    def body() -> dict:
        with cli_client as client:
            return client.health()

    result = await run_blocking(body)

    assert result["status"] == "ok"


async def test_cli_client_authenticated_whoami(cli_client: FastSMTPClient, run_blocking) -> None:
    """An authenticated whoami must reach the server and be accepted.

    Fails with a 404 if the client uses the wrong path prefix (issue #39) and
    with a 401 if it sends the wrong auth header (issue #40).
    """

    def body() -> dict:
        with cli_client as client:
            return client.whoami()

    result = await run_blocking(body)

    assert result["is_root"] is True
    assert result["user"]["username"] == "root"


async def test_cli_client_full_domain_lifecycle(cli_client: FastSMTPClient, run_blocking) -> None:
    """Drive the reconciled domain/recipient/ruleset/rule calls against the real app.

    Every one of these calls 404'd or 405'd before issue #46: rulesets, rules and
    recipients are nested under a domain, updates are PUT not PATCH, and the
    payloads carried fields (`description`, rule `name`/`priority`) the server's
    schemas never had.
    """

    def body() -> None:
        with cli_client as client:
            domain = client.create_domain("lifecycle.test", verify_dkim=True)
            domain_id = domain["id"]
            assert domain["verify_dkim"] is True

            domain = client.update_domain(domain_id, verify_dkim=None, reject_spf_fail=True)
            assert domain["verify_dkim"] is None, "explicit null must clear the override"
            assert domain["reject_spf_fail"] is True
            assert domain["is_enabled"] is True, "an omitted field must stay untouched"

            recipient = client.create_recipient(
                domain_id,
                webhook_url="https://hook.example.test/inbox",
                local_part="support",
                webhook_headers={"X-Token": "abc"},
            )
            recipient_id = recipient["id"]
            assert client.get_recipient(domain_id, recipient_id)["local_part"] == "support"
            updated_recipient = client.update_recipient(domain_id, recipient_id, is_enabled=False)
            assert updated_recipient["is_enabled"] is False

            ruleset_id = client.create_ruleset(domain_id, "Spam Filter", priority=10)["id"]
            assert client.update_ruleset(domain_id, ruleset_id, priority=20)["priority"] == 20

            first = client.create_rule(
                domain_id,
                ruleset_id,
                field="subject",
                operator="contains",
                value="[SPAM]",
                action="tag",
                add_tags=["spam"],
            )
            second = client.create_rule(
                domain_id,
                ruleset_id,
                field="from",
                operator="ends_with",
                value="@spam.test",
                action="drop",
            )

            rules = client.list_rules(domain_id, ruleset_id)
            assert {rule["id"] for rule in rules} == {first["id"], second["id"]}
            assert client.get_rule(domain_id, ruleset_id, second["id"])["action"] == "drop"

            assert (
                client.update_rule(domain_id, first["id"], action="quarantine")["action"]
                == "quarantine"
            )

            client.reorder_rules(domain_id, ruleset_id, [second["id"], first["id"]])
            reordered = sorted(
                client.list_rules(domain_id, ruleset_id), key=lambda rule: rule["order"]
            )
            assert [rule["id"] for rule in reordered] == [second["id"], first["id"]]

            client.delete_rule(domain_id, first["id"])
            remaining = client.list_rules(domain_id, ruleset_id)
            assert [rule["id"] for rule in remaining] == [second["id"]]

            client.delete_ruleset(domain_id, ruleset_id)
            client.delete_recipient(domain_id, recipient_id)
            client.delete_domain(domain_id)

    await run_blocking(body)


async def test_cli_client_reports_missing_s3_for_raw_preservation(
    cli_client: FastSMTPClient,
    run_blocking,
) -> None:
    """Raw preservation without S3 must surface the server's 422 detail as text."""

    def body() -> None:
        with cli_client as client:
            with pytest.raises(APIError) as exc_info:
                client.create_domain("preserve.test", preserve_raw_message=True)

            assert exc_info.value.status_code == 422
            assert isinstance(exc_info.value.detail, str)
            assert "S3" in exc_info.value.detail

            domain_id = client.create_domain("preserve-rules.test")["id"]
            ruleset_id = client.create_ruleset(domain_id, "Archive")["id"]

            with pytest.raises(APIError) as rule_exc_info:
                client.create_rule(
                    domain_id,
                    ruleset_id,
                    field="subject",
                    operator="exists",
                    value="",
                    preserve_raw=True,
                )

            assert rule_exc_info.value.status_code == 422
            assert "S3" in rule_exc_info.value.detail

    await run_blocking(body)


def _status(call) -> int:
    """Run a client call expected to fail and return the server's status code."""
    with pytest.raises(APIError) as exc_info:
        call()
    return exc_info.value.status_code


async def test_cli_client_domain_soft_delete_lifecycle(
    cli_client: FastSMTPClient, run_blocking
) -> None:
    """Domain: create, delete, hidden, audited, restored, deleted again, purged, gone.

    Drives the v0.5.0 soft-delete surface (#106) through the real server:
    ``include_deleted`` on list/get/delivery-log, ``restore``, the 409s for
    restoring a live row and purging one, and ``purge`` on a tombstone.
    """

    def body() -> None:
        with cli_client as client:
            domain_id = client.create_domain("softdelete.test")["id"]
            assert client.get_domain(domain_id)["deleted_at"] is None

            assert _status(lambda: client.restore_domain(domain_id)) == 409
            assert _status(lambda: client.delete_domain(domain_id, purge=True)) == 409

            client.delete_domain(domain_id)

            assert domain_id not in {d["id"] for d in client.list_domains()}
            tombstones = {d["id"]: d for d in client.list_domains(include_deleted=True)}
            assert tombstones[domain_id]["deleted_at"] is not None

            assert _status(lambda: client.get_domain(domain_id)) == 404
            assert client.get_domain(domain_id, include_deleted=True)["deleted_at"] is not None

            # History stays readable after the delete - the #106 payoff.
            assert _status(lambda: client.list_delivery_logs(domain_id)) == 404
            assert client.list_delivery_logs(domain_id, include_deleted=True) == []

            restored = client.restore_domain(domain_id)
            assert restored["deleted_at"] is None
            assert client.get_domain(domain_id)["domain_name"] == "softdelete.test"

            client.delete_domain(domain_id)
            client.delete_domain(domain_id, purge=True)
            assert _status(lambda: client.get_domain(domain_id, include_deleted=True)) == 404

    await run_blocking(body)


async def test_cli_client_recipient_soft_delete_lifecycle(
    cli_client: FastSMTPClient, run_blocking
) -> None:
    """Recipient: the same lifecycle under a live domain."""

    def body() -> None:
        with cli_client as client:
            domain_id = client.create_domain("softdelete-recipient.test")["id"]
            recipient_id = client.create_recipient(
                domain_id, webhook_url="https://hook.example.test/inbox", local_part="sales"
            )["id"]

            assert _status(lambda: client.restore_recipient(domain_id, recipient_id)) == 409
            assert (
                _status(lambda: client.delete_recipient(domain_id, recipient_id, purge=True)) == 409
            )

            client.delete_recipient(domain_id, recipient_id)

            assert client.list_recipients(domain_id) == []
            [tombstone] = client.list_recipients(domain_id, include_deleted=True)
            assert tombstone["id"] == recipient_id
            assert tombstone["deleted_at"] is not None

            assert _status(lambda: client.get_recipient(domain_id, recipient_id)) == 404
            shown = client.get_recipient(domain_id, recipient_id, include_deleted=True)
            assert shown["deleted_at"] is not None

            restored = client.restore_recipient(domain_id, recipient_id)
            assert restored["deleted_at"] is None
            assert client.get_recipient(domain_id, recipient_id)["local_part"] == "sales"

            client.delete_recipient(domain_id, recipient_id)
            client.delete_recipient(domain_id, recipient_id, purge=True)
            assert (
                _status(lambda: client.get_recipient(domain_id, recipient_id, include_deleted=True))
                == 404
            )

            client.delete_domain(domain_id)
            client.delete_domain(domain_id, purge=True)

    await run_blocking(body)


async def test_cli_client_user_soft_delete_lifecycle(
    cli_client: FastSMTPClient, run_blocking
) -> None:
    """User: delete hides the account, restore brings it back, purge removes it."""

    def body() -> None:
        with cli_client as client:
            user_id = client.create_user("softdelete-user", email="sd@example.test")["id"]

            client.delete_user(user_id)

            assert user_id not in {u["id"] for u in client.list_users()}
            tombstones = {u["id"]: u for u in client.list_users(include_deleted=True)}
            assert tombstones[user_id]["deleted_at"] is not None
            assert _status(lambda: client.get_user(user_id)) == 404
            assert client.get_user(user_id, include_deleted=True)["deleted_at"] is not None

            assert client.restore_user(user_id)["deleted_at"] is None
            assert client.get_user(user_id)["username"] == "softdelete-user"

            client.delete_user(user_id)
            client.delete_user(user_id, purge=True)
            assert _status(lambda: client.get_user(user_id, include_deleted=True)) == 404

            # The root key owns no keys; this only proves the server accepts the param.
            assert client.list_api_keys(include_deleted=True) == []

    await run_blocking(body)


async def test_cli_client_member_role_update(cli_client: FastSMTPClient, run_blocking) -> None:
    """Member role updates use PUT; the client sent PATCH, which 405'd."""

    def body() -> None:
        with cli_client as client:
            domain_id = client.create_domain("members.test")["id"]
            user = client.create_user("member-test-user", email="member@example.test")

            client.add_member(domain_id, user["id"], role="member")
            assert client.update_member(domain_id, user["id"], role="admin")["role"] == "admin"

            members = client.list_members(domain_id)
            assert any(member["user_id"] == user["id"] for member in members)

            client.remove_member(domain_id, user["id"])
            client.delete_user(user["id"])
            client.delete_domain(domain_id)

    await run_blocking(body)
