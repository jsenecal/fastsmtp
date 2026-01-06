"""HTTP API client for FastSMTP server."""

from typing import Any
from uuid import UUID

import httpx

from fastsmtp_cli.config import Profile, get_profile


class APIError(Exception):
    """API request error."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"API error {status_code}: {detail}")


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
                headers["Authorization"] = f"Bearer {self.profile.api_key}"

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
        return self.get("/api/health")

    def ready(self) -> dict:
        """Get server readiness status."""
        return self.get("/api/ready")

    # Auth endpoints

    def whoami(self) -> dict:
        """Get current authenticated user info."""
        return self.get("/api/auth/whoami")

    def list_api_keys(self) -> list[dict]:
        """List user's API keys."""
        return self.get("/api/auth/keys")

    def create_api_key(
        self,
        name: str,
        scopes: list[str] | None = None,
        expires_days: int | None = None,
    ) -> dict:
        """Create a new API key."""
        data: dict[str, Any] = {"name": name}
        if scopes:
            data["scopes"] = scopes
        if expires_days:
            data["expires_days"] = expires_days
        return self.post("/api/auth/keys", json=data)

    def delete_api_key(self, key_id: UUID | str) -> None:
        """Delete an API key."""
        self.delete(f"/api/auth/keys/{key_id}")

    def rotate_api_key(self, key_id: UUID | str) -> dict:
        """Rotate an API key."""
        return self.post(f"/api/auth/keys/{key_id}/rotate")

    # User endpoints (superuser only)

    def list_users(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """List all users."""
        return self.get("/api/users", params={"limit": limit, "offset": offset})

    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        is_superuser: bool = False,
    ) -> dict:
        """Create a new user."""
        return self.post(
            "/api/users",
            json={
                "username": username,
                "email": email,
                "password": password,
                "is_superuser": is_superuser,
            },
        )

    def get_user(self, user_id: UUID | str) -> dict:
        """Get a user by ID."""
        return self.get(f"/api/users/{user_id}")

    def update_user(
        self,
        user_id: UUID | str,
        username: str | None = None,
        email: str | None = None,
        password: str | None = None,
        is_active: bool | None = None,
        is_superuser: bool | None = None,
    ) -> dict:
        """Update a user."""
        data: dict[str, Any] = {}
        if username is not None:
            data["username"] = username
        if email is not None:
            data["email"] = email
        if password is not None:
            data["password"] = password
        if is_active is not None:
            data["is_active"] = is_active
        if is_superuser is not None:
            data["is_superuser"] = is_superuser
        return self.patch(f"/api/users/{user_id}", json=data)

    def delete_user(self, user_id: UUID | str) -> None:
        """Delete a user."""
        self.delete(f"/api/users/{user_id}")

    # Domain endpoints

    def list_domains(self, limit: int = 50, offset: int = 0) -> list[dict]:
        """List domains the user has access to."""
        return self.get("/api/domains", params={"limit": limit, "offset": offset})

    def create_domain(
        self,
        domain_name: str,
        description: str | None = None,
    ) -> dict:
        """Create a new domain."""
        data: dict[str, Any] = {"domain_name": domain_name}
        if description:
            data["description"] = description
        return self.post("/api/domains", json=data)

    def get_domain(self, domain_id: UUID | str) -> dict:
        """Get a domain by ID."""
        return self.get(f"/api/domains/{domain_id}")

    def update_domain(
        self,
        domain_id: UUID | str,
        description: str | None = None,
        is_enabled: bool | None = None,
    ) -> dict:
        """Update a domain."""
        data: dict[str, Any] = {}
        if description is not None:
            data["description"] = description
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        return self.patch(f"/api/domains/{domain_id}", json=data)

    def delete_domain(self, domain_id: UUID | str) -> None:
        """Delete a domain."""
        self.delete(f"/api/domains/{domain_id}")

    # Domain members

    def list_members(
        self,
        domain_id: UUID | str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """List domain members."""
        return self.get(
            f"/api/domains/{domain_id}/members",
            params={"limit": limit, "offset": offset},
        )

    def add_member(
        self,
        domain_id: UUID | str,
        user_id: UUID | str,
        role: str = "member",
    ) -> dict:
        """Add a member to a domain."""
        return self.post(
            f"/api/domains/{domain_id}/members",
            json={"user_id": str(user_id), "role": role},
        )

    def update_member(
        self,
        domain_id: UUID | str,
        user_id: UUID | str,
        role: str,
    ) -> dict:
        """Update a member's role."""
        return self.patch(
            f"/api/domains/{domain_id}/members/{user_id}",
            json={"role": role},
        )

    def remove_member(self, domain_id: UUID | str, user_id: UUID | str) -> None:
        """Remove a member from a domain."""
        self.delete(f"/api/domains/{domain_id}/members/{user_id}")

    # Recipient endpoints

    def list_recipients(
        self,
        domain_id: UUID | str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """List recipients for a domain."""
        return self.get(
            f"/api/domains/{domain_id}/recipients",
            params={"limit": limit, "offset": offset},
        )

    def create_recipient(
        self,
        domain_id: UUID | str,
        webhook_url: str,
        local_part: str | None = None,
        description: str | None = None,
        tags: list[str] | None = None,
    ) -> dict:
        """Create a new recipient."""
        data: dict[str, Any] = {"webhook_url": webhook_url}
        if local_part is not None:
            data["local_part"] = local_part
        if description:
            data["description"] = description
        if tags:
            data["tags"] = tags
        return self.post(f"/api/domains/{domain_id}/recipients", json=data)

    def get_recipient(self, recipient_id: UUID | str) -> dict:
        """Get a recipient by ID."""
        return self.get(f"/api/recipients/{recipient_id}")

    def update_recipient(
        self,
        recipient_id: UUID | str,
        local_part: str | None = None,
        webhook_url: str | None = None,
        description: str | None = None,
        is_enabled: bool | None = None,
        tags: list[str] | None = None,
    ) -> dict:
        """Update a recipient."""
        data: dict[str, Any] = {}
        if local_part is not None:
            data["local_part"] = local_part
        if webhook_url is not None:
            data["webhook_url"] = webhook_url
        if description is not None:
            data["description"] = description
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        if tags is not None:
            data["tags"] = tags
        return self.patch(f"/api/recipients/{recipient_id}", json=data)

    def delete_recipient(self, recipient_id: UUID | str) -> None:
        """Delete a recipient."""
        self.delete(f"/api/recipients/{recipient_id}")

    # RuleSet endpoints

    def list_rulesets(
        self,
        domain_id: UUID | str,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """List rulesets for a domain."""
        return self.get(
            f"/api/domains/{domain_id}/rulesets",
            params={"limit": limit, "offset": offset},
        )

    def create_ruleset(
        self,
        domain_id: UUID | str,
        name: str,
        description: str | None = None,
        priority: int = 0,
    ) -> dict:
        """Create a new ruleset."""
        data: dict[str, Any] = {"name": name, "priority": priority}
        if description:
            data["description"] = description
        return self.post(f"/api/domains/{domain_id}/rulesets", json=data)

    def get_ruleset(self, ruleset_id: UUID | str) -> dict:
        """Get a ruleset by ID."""
        return self.get(f"/api/rulesets/{ruleset_id}")

    def update_ruleset(
        self,
        ruleset_id: UUID | str,
        name: str | None = None,
        description: str | None = None,
        priority: int | None = None,
        is_enabled: bool | None = None,
    ) -> dict:
        """Update a ruleset."""
        data: dict[str, Any] = {}
        if name is not None:
            data["name"] = name
        if description is not None:
            data["description"] = description
        if priority is not None:
            data["priority"] = priority
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        return self.patch(f"/api/rulesets/{ruleset_id}", json=data)

    def delete_ruleset(self, ruleset_id: UUID | str) -> None:
        """Delete a ruleset."""
        self.delete(f"/api/rulesets/{ruleset_id}")

    # Rule endpoints

    def list_rules(self, ruleset_id: UUID | str) -> list[dict]:
        """List rules in a ruleset."""
        return self.get(f"/api/rulesets/{ruleset_id}/rules")

    def create_rule(
        self,
        ruleset_id: UUID | str,
        name: str,
        field: str,
        operator: str,
        value: str,
        action: str = "forward",
        action_params: dict | None = None,
        priority: int = 0,
    ) -> dict:
        """Create a new rule."""
        data: dict[str, Any] = {
            "name": name,
            "field": field,
            "operator": operator,
            "value": value,
            "action": action,
            "priority": priority,
        }
        if action_params:
            data["action_params"] = action_params
        return self.post(f"/api/rulesets/{ruleset_id}/rules", json=data)

    def get_rule(self, rule_id: UUID | str) -> dict:
        """Get a rule by ID."""
        return self.get(f"/api/rules/{rule_id}")

    def update_rule(
        self,
        rule_id: UUID | str,
        name: str | None = None,
        field: str | None = None,
        operator: str | None = None,
        value: str | None = None,
        action: str | None = None,
        action_params: dict | None = None,
        priority: int | None = None,
        is_enabled: bool | None = None,
    ) -> dict:
        """Update a rule."""
        data: dict[str, Any] = {}
        if name is not None:
            data["name"] = name
        if field is not None:
            data["field"] = field
        if operator is not None:
            data["operator"] = operator
        if value is not None:
            data["value"] = value
        if action is not None:
            data["action"] = action
        if action_params is not None:
            data["action_params"] = action_params
        if priority is not None:
            data["priority"] = priority
        if is_enabled is not None:
            data["is_enabled"] = is_enabled
        return self.patch(f"/api/rules/{rule_id}", json=data)

    def delete_rule(self, rule_id: UUID | str) -> None:
        """Delete a rule."""
        self.delete(f"/api/rules/{rule_id}")

    # Delivery log endpoints

    def list_delivery_logs(
        self,
        domain_id: UUID | str,
        status: str | None = None,
        message_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """List delivery logs for a domain."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status
        if message_id:
            params["message_id"] = message_id
        return self.get(f"/api/domains/{domain_id}/delivery-log", params=params)

    def get_delivery_log(self, log_id: UUID | str) -> dict:
        """Get a delivery log entry."""
        return self.get(f"/api/delivery-log/{log_id}")

    def retry_delivery(self, log_id: UUID | str) -> dict:
        """Retry a failed delivery."""
        return self.post(f"/api/delivery-log/{log_id}/retry")

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
            "/api/test-webhook",
            json={
                "webhook_url": webhook_url,
                "from_address": from_address,
                "to_address": to_address,
                "subject": subject,
                "body": body,
            },
        )
