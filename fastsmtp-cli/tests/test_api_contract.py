"""Contract tests between ``fastsmtp-cli`` and the FastSMTP server API.

The rest of the CLI test-suite mocks HTTP with ``respx``: the mocks are
registered against whatever URL the client happens to build, so they only ever
assert that the client agrees with itself.  That is how the client drifted 13
routes away from the server without a single test failing (issue #46).

These tests close that hole.  They build the *real* FastAPI application
in-process, take its OpenAPI document as the authoritative contract, and drive
every public method of :class:`FastSMTPClient` through a recording transport.
Every request the client emits is then checked against the contract:

* the path must match a route the server actually serves,
* with the HTTP method the client used,
* every query parameter must be declared on that operation,
* every JSON body field must exist on that operation's request schema, and
  every required field of that schema must be present.

Nothing here is hand-maintained: the method list comes from introspecting the
client, and the route/schema tables come from the server.  Adding a client
method, renaming a server route, or changing a request schema on either side
makes these tests fail until both sides agree again.
"""

import inspect
import json
import re
import types
from datetime import UTC, datetime
from typing import Any, Union, get_args, get_origin
from uuid import UUID, uuid4

import httpx
import pytest
import respx
from fastsmtp_cli.client import FastSMTPClient
from fastsmtp_cli.config import Profile

BASE_URL = "https://contract.example.test"

#: Generic HTTP verb helpers and lifecycle methods - they take a caller-supplied
#: path, so there is no contract of their own to check.
NON_ENDPOINT_METHODS = frozenset({"get", "post", "put", "patch", "delete", "close"})


# --------------------------------------------------------------------------- #
# The server side of the contract
# --------------------------------------------------------------------------- #


@pytest.fixture(scope="module")
def openapi() -> dict[str, Any]:
    """The real server's OpenAPI document, built in-process."""
    from fastsmtp.config import Settings
    from fastsmtp.main import create_app

    app = create_app(
        Settings(
            database_url="sqlite+aiosqlite:///:memory:",
            root_api_key="contract-test-root-key",
        )
    )
    return app.openapi()


def _path_pattern(template: str) -> re.Pattern[str]:
    """Compile an OpenAPI path template into a matcher for concrete paths."""
    parts = [re.escape(part) for part in re.split(r"\{[^}]+\}", template)]
    return re.compile("^" + "[^/]+".join(parts) + "$")


def _resolve(spec: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    """Resolve a (possibly ``$ref``) schema against the OpenAPI components."""
    ref = schema.get("$ref")
    if ref is None:
        return schema
    node: Any = spec
    for key in ref.removeprefix("#/").split("/"):
        node = node[key]
    return _resolve(spec, node)


def _match_route(spec: dict[str, Any], path: str) -> str:
    """Return the OpenAPI path template serving ``path``.

    Raises:
        AssertionError: if the server serves no route for this path.
    """
    if path in spec["paths"]:
        return path
    matches = [t for t in spec["paths"] if _path_pattern(t).match(path)]
    assert matches, (
        f"the client called {path!r}, which no server route matches.\n"
        f"Server routes:\n  " + "\n  ".join(sorted(spec["paths"]))
    )
    assert len(matches) == 1, f"{path!r} matches several server routes: {matches}"
    return matches[0]


def _operation(spec: dict[str, Any], request: httpx.Request) -> dict[str, Any]:
    """Return the OpenAPI operation the request targets, asserting it exists."""
    template = _match_route(spec, request.url.path)
    operations = spec["paths"][template]
    method = request.method.lower()
    assert method in operations, (
        f"the client sent {request.method} {request.url.path}, but the server only "
        f"serves {', '.join(sorted(m.upper() for m in operations))} on {template}"
    )
    return operations[method]


# --------------------------------------------------------------------------- #
# The client side of the contract
# --------------------------------------------------------------------------- #


def endpoint_methods() -> list[str]:
    """Every public :class:`FastSMTPClient` method that talks to the server."""
    return sorted(
        name
        for name, _ in inspect.getmembers(FastSMTPClient, inspect.isfunction)
        if not name.startswith("_") and name not in NON_ENDPOINT_METHODS
    )


def _sample_value(name: str, annotation: Any) -> Any:
    """Build a plausible argument value for a client parameter.

    Deliberately strict: an annotation this does not understand raises, so a new
    client method cannot quietly escape contract checking.
    """
    origin = get_origin(annotation)
    if origin in (Union, types.UnionType):
        # Always supply a value for optional parameters so that every field the
        # client is capable of sending is exercised against the server schema.
        candidates = [arg for arg in get_args(annotation) if arg is not type(None)]
        return _sample_value(name, candidates[0])
    if origin is list:
        return [_sample_value(name, get_args(annotation)[0])]
    if origin is dict or annotation is dict:
        return {"X-Contract-Test": "1"}
    if annotation is UUID:
        return str(uuid4())
    if annotation is bool:
        return True
    if annotation is int:
        return 1
    if annotation is float:
        return 1.0
    if annotation is datetime:
        return datetime(2030, 1, 1, tzinfo=UTC)
    if annotation is str:
        if name.endswith("_id"):
            return str(uuid4())
        if "url" in name:
            return "https://webhook.example.test/hook"
        if "address" in name or name == "email":
            return "contract@example.test"
        if name == "field":
            return "subject"
        if name == "operator":
            return "contains"
        if name == "action":
            return "tag"
        if name == "role":
            return "admin"
        return f"contract-{name}"
    raise AssertionError(
        f"the contract test cannot build a value for parameter {name!r} of type "
        f"{annotation!r}. Teach _sample_value about it so the new client method "
        f"stays covered."
    )


def _sample_kwargs(method: Any) -> dict[str, Any]:
    """Build a full set of arguments for a client method, optionals included."""
    signature = inspect.signature(method)
    return {
        name: _sample_value(name, parameter.annotation)
        for name, parameter in signature.parameters.items()
        if name != "self"
    }


@pytest.fixture
def route() -> Any:
    """Catch-all respx route recording every request the client makes."""
    with respx.mock:
        yield respx.route().mock(
            return_value=httpx.Response(200, json={"id": str(uuid4()), "rules": []})
        )


def _drive(method_name: str, route: Any) -> list[httpx.Request]:
    """Call one client method with generated arguments; return its requests."""
    method = getattr(FastSMTPClient, method_name)
    route.calls.clear()
    with FastSMTPClient(profile=Profile(url=BASE_URL, api_key="contract-key")) as client:
        try:
            method(client, **_sample_kwargs(method))
        except Exception as exc:  # noqa: BLE001 - responses are canned, not real
            # The canned response cannot satisfy every method (a client-side
            # lookup may not find its record in it). What the request looked
            # like is still recorded, and that is all this test judges.
            failure = exc
        else:
            failure = None

    requests = [call.request for call in route.calls]
    assert requests, f"{method_name}() made no HTTP request (raised {failure!r})"
    return requests


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("method_name", endpoint_methods())
def test_client_request_matches_server_contract(
    method_name: str, openapi: dict[str, Any], route: Any
) -> None:
    """Every request a client method makes must match a real server operation."""
    for request in _drive(method_name, route):
        operation = _operation(openapi, request)
        where = f"{method_name}() -> {request.method} {request.url.path}"

        declared = {
            parameter["name"]
            for parameter in operation.get("parameters", [])
            if parameter["in"] == "query"
        }
        sent = set(request.url.params.keys())
        assert sent <= declared, (
            f"{where} sends query parameters the server does not accept: "
            f"{sorted(sent - declared)} (accepted: {sorted(declared) or 'none'})"
        )

        request_body = operation.get("requestBody", {})
        body_schema = request_body.get("content", {}).get("application/json", {}).get("schema")
        if not request.content:
            continue
        assert body_schema is not None, f"{where} sends a body, but the server accepts none"

        schema = _resolve(openapi, body_schema)
        allowed = set(schema.get("properties", {}))
        required = set(schema.get("required", []))
        sent_fields = set(json.loads(request.content))
        assert sent_fields <= allowed, (
            f"{where} sends fields the server schema does not define: "
            f"{sorted(sent_fields - allowed)} (schema accepts: {sorted(allowed)})"
        )
        assert required <= sent_fields, (
            f"{where} omits fields the server requires: {sorted(required - sent_fields)}"
        )


def test_every_server_route_has_a_client_method(openapi: dict[str, Any], route: Any) -> None:
    """No server operation may be unreachable from the client.

    This is the half of the contract that catches *new* server routes: adding
    one without a client method fails here, forcing a deliberate decision.
    """
    served = {
        (template, method)
        for template, operations in openapi["paths"].items()
        for method in operations
    }

    reached: set[tuple[str, str]] = set()
    for method_name in endpoint_methods():
        for request in _drive(method_name, route):
            reached.add((_match_route(openapi, request.url.path), request.method.lower()))

    missing = served - reached
    assert not missing, "server routes no client method reaches: " + ", ".join(
        f"{method.upper()} {template}" for template, method in sorted(missing)
    )
