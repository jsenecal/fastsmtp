"""HTTP API client for FastSMTP server.

Every path and payload here mirrors a route the server actually serves. The
contract is enforced by ``fastsmtp-cli/tests/test_api_contract.py``, which drives
these methods against the server's own OpenAPI document - keep them in step.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

import httpx

from fastsmtp_cli.config import Profile, get_profile


class _Unset:
    """Sentinel type: a field the caller did not mention at all.

    Needed by the update methods because the server distinguishes "leave this
    column alone" (field absent from the JSON body) from "reset this column to
    null, i.e. inherit the global default" (field present and null).
    """

    _instance: "_Unset | None" = None

    def __new__(cls) -> "_Unset":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "UNSET"

    def __bool__(self) -> bool:
        return False


#: Marker for "field not provided" in update calls.
UNSET = _Unset()

#: A nullable boolean setting on an update call: ``True``/``False`` set it,
#: ``None`` resets it to inherit the server-wide default, ``UNSET`` leaves it be.
NullableBool = bool | None | _Unset

#: A nullable string column on an update call: a string sets it, ``None``
#: clears it (sent as JSON null), ``UNSET`` leaves it untouched.
NullableStr = str | None | _Unset


def _format_detail(detail: Any) -> str:
    """Render an error ``detail`` payload as a single human-readable string.

    FastAPI returns a string for ``HTTPException`` (for example the 422 raised
    when raw-message preservation is requested without S3 configured) but a list
    of error objects for request-validation failures. Commands print this
    straight to the terminal, so it must always be text.
    """
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        messages = []
        for item in detail:
            if isinstance(item, dict):
                location = ".".join(str(part) for part in item.get("loc", []) if part != "body")
                message = item.get("msg", "invalid value")
                messages.append(f"{location}: {message}" if location else str(message))
            else:
                messages.append(str(item))
        return "; ".join(messages)
    return str(detail)


class APIError(Exception):
    """API request error."""

    def __init__(self, status_code: int, detail: Any):
        self.status_code = status_code
        self.detail = _format_detail(detail)
        super().__init__(f"API error {status_code}: {self.detail}")


def _flags(**flags: bool) -> dict[str, str]:
    """Query params for boolean flags, sent only when true.

    Omitting false flags keeps requests byte-identical for older servers that
    do not declare them. An empty dict yields no query string at all, so the
    result can be passed as ``params=`` or merged into other params alike.
    """
    return {name: "true" for name, value in flags.items() if value}


class FastSMTPClient:
    """HTTP client for FastSMTP API."""

    def __init__(self, profile: Profile | None = None, profile_name: str | None = None):
        """Initialize client with a profile.

        Args:
            profile: Profile to use directly
            profile_name: Name of profile to load from config
        """
        self.profile = profile or get_profile(profile_name)
        self._client: httpx.Client | None = None

    def _get_client(self) -> httpx.Client:
        """Get or create HTTP client."""
        if self._client is None:
            headers = {}
            if self.profile.api_key:
                headers["X-API-Key"] = self.profile.api_key

            self._client = httpx.Client(
                base_url=self.profile.url,
                headers=headers,
                timeout=self.profile.timeout,
                verify=self.profile.verify_ssl,
            )
        return self._client

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "FastSMTPClient":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> Any:
        """Make an API request."""
        client = self._get_client()
        response = client.request(method, path, **kwargs)

        if response.status_code >= 400:
            try:
                detail = response.json().get("detail", response.text)
            except Exception:
                detail = response.text
            raise APIError(response.status_code, detail)

        if response.status_code == 204:
            return None

        return response.json()

    def get(self, path: str, **kwargs: Any) -> Any:
        """Make a GET request."""
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> Any:
        """Make a POST request."""
        return self._request("POST", path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> Any:
        """Make a PUT request."""
        return self._request("PUT", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> Any:
        """Make a PATCH request."""
        return self._request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> Any:
        """Make a DELETE request."""
        return self._request("DELETE", path, **kwargs)

    # Health endpoints

    def health(self) -> dict:
        """Get server health status."""
        return self.get("/api/v1/health")

    def ready(self) -> dict:
        """Get server readiness status."""
        return self.get("/api/v1/ready")

    # Auth endpoints

    def whoami(self) -> dict:
        """Get current authenticated user info."""
        return self.get("/api/v1/auth/me")

    def list_api_keys(self, include_deleted: bool = False) -> list[dict]:
        """List the caller's active API keys.

        ``include_deleted`` also returns deleted and retired ones. Keys cannot
        be restored; the listing exists so an operator can audit them.
        """
        return self.get("/api/v1/auth/keys", params=_flags(include_deleted=include_deleted))

    def create_api_key(
        self,
        name: str,
        scopes: list[str] | None = None,
        expires_at: datetime | None = None,
    ) -> dict:
        """Create a new API key."""
        data: dict[str, Any] = {"name": name}
        if scopes:
            data["scopes"] = scopes
        if expires_at is not None:
            data["expires_at"] = expires_at.isoformat()
        return self.post("/api/v1/auth/keys", json=data)

    def delete_api_key(self, key_id: UUID | str) -> None:
        """Delete an API key."""
        self.delete(f"/api/v1/auth/keys/{key_id}")

    def rotate_api_key(self, key_id: UUID | str) -> dict:
        """Rotate an API key."""
        return self.post(f"/api/v1/auth/keys/{key_id}/rotate")

    # User endpoints (superuser only)

    def list_users(self, include_deleted: bool = False) -> list[dict]:
        """List all users. ``include_deleted`` also returns soft-deleted ones."""
        return self.get("/api/v1/users", params=_flags(include_deleted=include_deleted))

    def create_user(
        self,
        username: str,
        email: str | None = None,
        is_superuser: bool = False,
    ) -> dict:
        """Create a new user."""
        data: dict[str, Any] = {"username": username, "is_superuser": is_superuser}
        if email is not None:
            data["email"] = email
        return self.post("/api/v1/users", json=data)

    def get_user(self, user_id: UUID | str, include_deleted: bool = False) -> dict:
        """Get a user by ID. A soft-deleted user is 404 unless ``include_deleted``."""
        return self.get(f"/api/v1/users/{user_id}", params=_flags(include_deleted=include_deleted))

    def update_user(
        self,
        user_id: UUID | str,
        username: str | None = None,
        email: NullableStr = UNSET,
        is_active: bool | None = None,
        is_superuser: bool | None = None,
    ) -> dict:
        """Update a user.

        ``email`` is three-valued: a string sets it, ``None`` clears the
        column (sent as JSON null), ``UNSET`` leaves it untouched. ``username``
        is NOT NULL server-side, so it cannot be cleared, only replaced.
        """
        data: dict[str, Any] = {}
        if username is not None:
            data["username"] = username
        if not isinstance(email, _Unset):
            data["email"] = email
        if is_active is not None:
            data["is_active"] = is_active
        if is_superuser is not None:
            data["is_superuser"] = is_superuser
        return self.put(f"/api/v1/users/{user_id}", json=data)

    def delete_user(self, user_id: UUID | str, purge: bool = False) -> None:
        """Soft-delete a user; ``purge`` permanently removes an already-deleted one."""
        self.delete(f"/api/v1/users/{user_id}", params=_flags(purge=purge))

    def restore_user(self, user_id: UUID | str) -> dict:
        """Restore a soft-deleted user. API keys revoked at deletion stay revoked."""
        return self.post(f"/api/v1/users/{user_id}/restore")

    # Domain endpoints

    def list_domains(self, include_deleted: bool = False) -> list[dict]:
        """List domains the user has access to.

        ``include_deleted`` also returns soft-deleted ones: all of them for a
        superuser, only those the caller owns otherwise.
        """
        return self.get("/api/v1/domains", params=_flags(include_deleted=include_deleted))

    def create_domain(
        self,
        domain_name: str,
        verify_dkim: bool | None = None,
        verify_spf: bool | None = None,
        reject_dkim_fail: bool | None = None,
        reject_spf_fail: bool | None = None,
        preserve_raw_message: bool | None = None,
    ) -> dict:
        """Create a new domain.

        Any flag left as ``None`` is omitted, so the domain inherits the
        server-wide default for that setting.
        """
        data: dict[str, Any] = {"domain_name": domain_name}
        if verify_dkim is not None:
            data["verify_dkim"] = verify_dkim
        if verify_spf is not None:
            data["verify_spf"] = verify_spf
        if reject_dkim_fail is not None:
            data["reject_dkim_fail"] = reject_dkim_fail
        if reject_spf_fail is not None:
            data["reject_spf_fail"] = reject_spf_fail
        if preserve_raw_message is not None:
            data["preserve_raw_message"] = preserve_raw_message
        return self.post("/api/v1/domains", json=data)

    def get_domain(self, domain_id: UUID | str, include_deleted: bool = False) -> dict:
        """Get a domain by ID. A soft-deleted domain is 404 unless ``include_deleted``."""
        return self.get(
            f"/api/v1/domains/{domain_id}", params=_flags(include_deleted=include_deleted)
        )

    def update_domain(
        self,
        domain_id: UUID | str,
        is_enabled: bool | None = None,
        verify_dkim: NullableBool = UNSET,
        verify_spf: NullableBool = UNSET,
        reject_dkim_fail: NullableBool = UNSET,
        reject_spf_fail: NullableBool = UNSET,
        preserve_raw_message: NullableBool = UNSET,
    ) -> dict:
        """Update a domain.

        The nullable flags are three-valued: ``True``/``False`` pin the setting
        for this domain, ``None`` clears it so the domain inherits the
        server-wide default, and ``UNSET`` leaves it untouched.
        """
        data: dict[str, Any] = {}
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        for field, value in (
            ("verify_dkim", verify_dkim),
            ("verify_spf", verify_spf),
            ("reject_dkim_fail", reject_dkim_fail),
            ("reject_spf_fail", reject_spf_fail),
            ("preserve_raw_message", preserve_raw_message),
        ):
            if not isinstance(value, _Unset):
                data[field] = value
        return self.put(f"/api/v1/domains/{domain_id}", json=data)

    def delete_domain(self, domain_id: UUID | str, purge: bool = False) -> None:
        """Soft-delete a domain; ``purge`` permanently removes an already-deleted one."""
        self.delete(f"/api/v1/domains/{domain_id}", params=_flags(purge=purge))

    def restore_domain(self, domain_id: UUID | str) -> dict:
        """Restore a soft-deleted domain and the recipients deleted with it."""
        return self.post(f"/api/v1/domains/{domain_id}/restore")

    # Domain members

    def list_members(self, domain_id: UUID | str) -> list[dict]:
        """List domain members."""
        return self.get(f"/api/v1/domains/{domain_id}/members")

    def add_member(
        self,
        domain_id: UUID | str,
        user_id: UUID | str,
        role: str = "member",
    ) -> dict:
        """Add a member to a domain."""
        return self.post(
            f"/api/v1/domains/{domain_id}/members",
            json={"user_id": str(user_id), "role": role},
        )

    def update_member(
        self,
        domain_id: UUID | str,
        user_id: UUID | str,
        role: str,
    ) -> dict:
        """Update a member's role."""
        return self.put(
            f"/api/v1/domains/{domain_id}/members/{user_id}",
            json={"role": role},
        )

    def remove_member(self, domain_id: UUID | str, user_id: UUID | str) -> None:
        """Remove a member from a domain."""
        self.delete(f"/api/v1/domains/{domain_id}/members/{user_id}")

    # Recipient endpoints

    def list_recipients(self, domain_id: UUID | str, include_deleted: bool = False) -> list[dict]:
        """List recipients for a domain. ``include_deleted`` also returns soft-deleted ones."""
        return self.get(
            f"/api/v1/domains/{domain_id}/recipients",
            params=_flags(include_deleted=include_deleted),
        )

    def create_recipient(
        self,
        domain_id: UUID | str,
        webhook_url: str,
        local_part: str | None = None,
        webhook_headers: dict | None = None,
    ) -> dict:
        """Create a new recipient."""
        data: dict[str, Any] = {"webhook_url": webhook_url}
        if local_part is not None:
            data["local_part"] = local_part
        if webhook_headers:
            data["webhook_headers"] = webhook_headers
        return self.post(f"/api/v1/domains/{domain_id}/recipients", json=data)

    def get_recipient(
        self, domain_id: UUID | str, recipient_id: UUID | str, include_deleted: bool = False
    ) -> dict:
        """Get a recipient by ID. A soft-deleted recipient is 404 unless ``include_deleted``."""
        return self.get(
            f"/api/v1/domains/{domain_id}/recipients/{recipient_id}",
            params=_flags(include_deleted=include_deleted),
        )

    def update_recipient(
        self,
        domain_id: UUID | str,
        recipient_id: UUID | str,
        local_part: NullableStr = UNSET,
        webhook_url: str | None = None,
        is_enabled: bool | None = None,
        webhook_headers: dict | None = None,
    ) -> dict:
        """Update a recipient.

        ``local_part`` is three-valued: a string sets it, ``None`` clears the
        column (sent as JSON null) which turns the recipient into the domain's
        catch-all, ``UNSET`` leaves it untouched.
        """
        data: dict[str, Any] = {}
        if not isinstance(local_part, _Unset):
            data["local_part"] = local_part
        if webhook_url is not None:
            data["webhook_url"] = webhook_url
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        if webhook_headers is not None:
            data["webhook_headers"] = webhook_headers
        return self.put(f"/api/v1/domains/{domain_id}/recipients/{recipient_id}", json=data)

    def delete_recipient(
        self, domain_id: UUID | str, recipient_id: UUID | str, purge: bool = False
    ) -> None:
        """Soft-delete a recipient; ``purge`` permanently removes an already-deleted one."""
        self.delete(
            f"/api/v1/domains/{domain_id}/recipients/{recipient_id}",
            params=_flags(purge=purge),
        )

    def restore_recipient(self, domain_id: UUID | str, recipient_id: UUID | str) -> dict:
        """Restore a soft-deleted recipient. Cancelled deliveries stay cancelled."""
        return self.post(f"/api/v1/domains/{domain_id}/recipients/{recipient_id}/restore")

    # RuleSet endpoints

    def list_rulesets(self, domain_id: UUID | str) -> list[dict]:
        """List rulesets for a domain."""
        return self.get(f"/api/v1/domains/{domain_id}/rulesets")

    def create_ruleset(
        self,
        domain_id: UUID | str,
        name: str,
        priority: int = 0,
        stop_on_match: bool = True,
    ) -> dict:
        """Create a new ruleset."""
        data: dict[str, Any] = {
            "name": name,
            "priority": priority,
            "stop_on_match": stop_on_match,
        }
        return self.post(f"/api/v1/domains/{domain_id}/rulesets", json=data)

    def get_ruleset(self, domain_id: UUID | str, ruleset_id: UUID | str) -> dict:
        """Get a ruleset by ID, including its rules."""
        return self.get(f"/api/v1/domains/{domain_id}/rulesets/{ruleset_id}")

    def update_ruleset(
        self,
        domain_id: UUID | str,
        ruleset_id: UUID | str,
        name: str | None = None,
        priority: int | None = None,
        stop_on_match: bool | None = None,
        is_enabled: bool | None = None,
    ) -> dict:
        """Update a ruleset."""
        data: dict[str, Any] = {}
        if name is not None:
            data["name"] = name
        if priority is not None:
            data["priority"] = priority
        if stop_on_match is not None:
            data["stop_on_match"] = stop_on_match
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        return self.put(f"/api/v1/domains/{domain_id}/rulesets/{ruleset_id}", json=data)

    def delete_ruleset(self, domain_id: UUID | str, ruleset_id: UUID | str) -> None:
        """Delete a ruleset."""
        self.delete(f"/api/v1/domains/{domain_id}/rulesets/{ruleset_id}")

    # Rule endpoints

    def list_rules(self, domain_id: UUID | str, ruleset_id: UUID | str) -> list[dict]:
        """List rules in a ruleset.

        The server has no standalone rules collection: rules are returned inside
        the ruleset detail response, in ``order`` order.
        """
        ruleset = self.get_ruleset(domain_id, ruleset_id)
        return ruleset.get("rules", [])

    def create_rule(
        self,
        domain_id: UUID | str,
        ruleset_id: UUID | str,
        field: str,
        operator: str,
        value: str,
        action: str = "forward",
        case_sensitive: bool = False,
        webhook_url_override: str | None = None,
        add_tags: list[str] | None = None,
        preserve_raw: bool = False,
    ) -> dict:
        """Create a new rule.

        The rule is appended to the end of the ruleset; use
        :meth:`reorder_rules` to change evaluation order.
        """
        data: dict[str, Any] = {
            "field": field,
            "operator": operator,
            "value": value,
            "action": action,
            "case_sensitive": case_sensitive,
            "preserve_raw": preserve_raw,
        }
        if webhook_url_override is not None:
            data["webhook_url_override"] = webhook_url_override
        if add_tags:
            data["add_tags"] = add_tags
        return self.post(f"/api/v1/domains/{domain_id}/rulesets/{ruleset_id}/rules", json=data)

    def get_rule(
        self,
        domain_id: UUID | str,
        ruleset_id: UUID | str,
        rule_id: UUID | str,
    ) -> dict:
        """Get a single rule out of its ruleset.

        The server exposes no standalone rule read endpoint, so the rule is
        picked out of the ruleset detail response.

        Raises:
            APIError: 404 if the ruleset holds no rule with that ID
        """
        for rule in self.list_rules(domain_id, ruleset_id):
            if str(rule.get("id")) == str(rule_id):
                return rule
        raise APIError(404, f"Rule {rule_id} not found in ruleset {ruleset_id}")

    def update_rule(
        self,
        domain_id: UUID | str,
        rule_id: UUID | str,
        field: str | None = None,
        operator: str | None = None,
        value: str | None = None,
        action: str | None = None,
        case_sensitive: bool | None = None,
        webhook_url_override: NullableStr = UNSET,
        add_tags: list[str] | None = None,
        preserve_raw: bool | None = None,
    ) -> dict:
        """Update a rule.

        ``webhook_url_override`` is three-valued: a string sets it, ``None``
        clears the override (sent as JSON null) so the rule falls back to the
        recipient's webhook URL, ``UNSET`` leaves it untouched.
        """
        data: dict[str, Any] = {}
        if field is not None:
            data["field"] = field
        if operator is not None:
            data["operator"] = operator
        if value is not None:
            data["value"] = value
        if action is not None:
            data["action"] = action
        if case_sensitive is not None:
            data["case_sensitive"] = case_sensitive
        if not isinstance(webhook_url_override, _Unset):
            data["webhook_url_override"] = webhook_url_override
        if add_tags is not None:
            data["add_tags"] = add_tags
        if preserve_raw is not None:
            data["preserve_raw"] = preserve_raw
        return self.put(f"/api/v1/domains/{domain_id}/rules/{rule_id}", json=data)

    def delete_rule(self, domain_id: UUID | str, rule_id: UUID | str) -> None:
        """Delete a rule."""
        self.delete(f"/api/v1/domains/{domain_id}/rules/{rule_id}")

    def reorder_rules(
        self,
        domain_id: UUID | str,
        ruleset_id: UUID | str,
        rule_ids: list[str],
    ) -> dict:
        """Set the evaluation order of a ruleset's rules."""
        return self.post(
            f"/api/v1/domains/{domain_id}/rulesets/{ruleset_id}/reorder",
            json={"rule_ids": [str(rule_id) for rule_id in rule_ids]},
        )

    # Delivery log endpoints

    def list_delivery_logs(
        self,
        domain_id: UUID | str,
        status: str | None = None,
        message_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
        include_deleted: bool = False,
    ) -> list[dict]:
        """List delivery logs for a domain.

        ``include_deleted`` resolves a soft-deleted domain too (owner or
        superuser only), so its history stays readable after the delete.
        """
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if message_id:
            params["message_id"] = message_id
        params.update(_flags(include_deleted=include_deleted))
        return self.get(f"/api/v1/domains/{domain_id}/delivery-log", params=params)

    def get_delivery_log(self, log_id: UUID | str) -> dict:
        """Get a delivery log entry."""
        return self.get(f"/api/v1/delivery-log/{log_id}")

    def retry_delivery(self, log_id: UUID | str) -> dict:
        """Retry a failed delivery."""
        return self.post(f"/api/v1/delivery-log/{log_id}/retry")

    # Test webhook

    def test_webhook(
        self,
        webhook_url: str,
        from_address: str = "test@example.com",
        to_address: str = "recipient@example.com",
        subject: str = "Test Email",
        body: str = "This is a test email from FastSMTP.",
    ) -> dict:
        """Test a webhook URL."""
        return self.post(
            "/api/v1/test-webhook",
            json={
                "webhook_url": webhook_url,
                "from_address": from_address,
                "to_address": to_address,
                "subject": subject,
                "body": body,
            },
        )
