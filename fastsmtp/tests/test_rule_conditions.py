"""Compound rule conditions: ``match: all|any`` over a list, with negation.

Until issue #182 a rule tested exactly one condition, and rules in a ruleset
combine as an OR, so there was no way to say AND and no way to say NOT. The
motivating policy is a mail-loop guard: drop mail *from our own sending
address* AND *marked Auto-Submitted other than "no"*. No single condition
expresses that without dropping something wanted.

The claims under test:

* **``all`` needs every condition, ``any`` needs one**, evaluated in stored
  order and short-circuiting on the first condition that decides.
* **A missing field is false, so negating it is true.** ``negate`` + ``exists``
  means "absent", and "NOT contains X" holds for a message without the field.
* **A negated multi-valued condition means no part matches**, not "some part
  does not match", which would almost always be true.
* **The API takes the new shape and the legacy flat one**, never both, and
  echoes the flat fields (deprecated) for a rule they can still describe.
"""

import logging
import uuid
from datetime import datetime
from email.message import EmailMessage
from unittest.mock import patch

import pytest
import pytest_asyncio
from fastsmtp.db.models import Domain, Rule, RuleSet
from fastsmtp.rules import engine
from fastsmtp.rules.engine import evaluate_rule, evaluate_rules
from fastsmtp.schemas.rule import (
    MAX_RULE_CONDITIONS,
    RuleCreate,
    RuleResponse,
    RuleUpdate,
)
from httpx import AsyncClient
from pydantic import ValidationError
from rule_helpers import make_compound_rule, make_condition, make_rule
from sqlalchemy.ext.asyncio import AsyncSession


def _message(**headers: str) -> EmailMessage:
    message = EmailMessage()
    for name, value in headers.items():
        message[name.replace("_", "-")] = value
    return message


# The loop guard from the issue, verbatim.
LOOP_GUARD = [
    ("from", "regex", r"^(noreply|support)@example\.com$"),
    ("header:Auto-Submitted", "exists"),
    ("header:Auto-Submitted", "equals", "no", False, True),
]


class TestMatchModes:
    @pytest.mark.parametrize(
        ("subject", "sender", "expected"),
        [
            ("invoice", "billing@example.com", True),
            ("invoice", "someone@other.org", False),
            ("hello", "billing@example.com", False),
            ("hello", "someone@other.org", False),
        ],
    )
    def test_all_needs_every_condition(self, subject: str, sender: str, expected: bool):
        rule = make_compound_rule(
            "all", [("subject", "contains", "invoice"), ("from", "ends_with", "@example.com")]
        )
        message = _message(Subject=subject, From=sender)

        assert evaluate_rule(rule, message, {}) is expected

    @pytest.mark.parametrize(
        ("subject", "sender", "expected"),
        [
            ("invoice", "billing@example.com", True),
            ("invoice", "someone@other.org", True),
            ("hello", "billing@example.com", True),
            ("hello", "someone@other.org", False),
        ],
    )
    def test_any_needs_one_condition(self, subject: str, sender: str, expected: bool):
        rule = make_compound_rule(
            "any", [("subject", "contains", "invoice"), ("from", "ends_with", "@example.com")]
        )
        message = _message(Subject=subject, From=sender)

        assert evaluate_rule(rule, message, {}) is expected

    def test_all_with_three_conditions(self):
        rule = make_compound_rule(
            "all",
            [
                ("subject", "contains", "invoice"),
                ("from", "ends_with", "@example.com"),
                ("header:X-Priority", "equals", "1"),
            ],
        )
        hit = _message(Subject="invoice", From="a@example.com", X_Priority="1")
        miss = _message(Subject="invoice", From="a@example.com", X_Priority="3")

        assert evaluate_rule(rule, hit, {}) is True
        assert evaluate_rule(rule, miss, {}) is False

    def test_all_short_circuits_on_the_first_false(self):
        rule = make_compound_rule(
            "all", [("subject", "contains", "nope"), ("from", "contains", "x")]
        )
        with patch.object(
            engine, "extract_field_values", wraps=engine.extract_field_values
        ) as extract:
            assert evaluate_rule(rule, _message(Subject="hi", From="x@y"), {}) is False

        assert [call.args[0] for call in extract.call_args_list] == ["subject"]

    def test_any_short_circuits_on_the_first_true(self):
        rule = make_compound_rule("any", [("subject", "contains", "hi"), ("from", "contains", "x")])
        with patch.object(
            engine, "extract_field_values", wraps=engine.extract_field_values
        ) as extract:
            assert evaluate_rule(rule, _message(Subject="hi", From="x@y"), {}) is True

        assert [call.args[0] for call in extract.call_args_list] == ["subject"]

    def test_conditions_run_in_stored_order_not_list_order(self):
        """``order`` decides, so a collection loaded out of order still short-circuits right."""
        rule = make_compound_rule(
            "all", [("subject", "contains", "nope"), ("from", "contains", "x")]
        )
        rule.conditions[0].order, rule.conditions[1].order = 1, 0
        with patch.object(
            engine, "extract_field_values", wraps=engine.extract_field_values
        ) as extract:
            evaluate_rule(rule, _message(Subject="hi", From="x@y"), {})

        assert [call.args[0] for call in extract.call_args_list] == ["from", "subject"]

    @pytest.mark.parametrize("match", ["all", "any"])
    def test_a_rule_without_conditions_matches_nothing(self, match: str):
        """``all`` over nothing would be vacuously true - a drop rule would eat every message."""
        rule = Rule(match=match, conditions=[])

        assert evaluate_rule(rule, _message(Subject="hi"), {}) is False


class TestNegation:
    def test_negate_inverts_a_present_field(self):
        positive = make_rule("subject", "contains", "spam")
        negative = make_rule("subject", "contains", "spam", negate=True)

        assert evaluate_rule(positive, _message(Subject="spam!"), {}) is True
        assert evaluate_rule(negative, _message(Subject="spam!"), {}) is False
        assert evaluate_rule(negative, _message(Subject="ham"), {}) is True

    def test_a_missing_field_is_false(self):
        rule = make_rule("header:X-Foo", "contains", "bar")

        assert evaluate_rule(rule, _message(Subject="hi"), {}) is False

    def test_a_negated_missing_field_is_true(self):
        """The classic surprise, pinned: NOT contains holds when the header is absent."""
        rule = make_rule("header:X-Foo", "contains", "bar", negate=True)

        assert evaluate_rule(rule, _message(Subject="hi"), {}) is True

    def test_negated_exists_means_absent(self):
        rule = make_rule("header:Auto-Submitted", "exists", negate=True)

        assert evaluate_rule(rule, _message(Subject="hi"), {}) is True
        assert evaluate_rule(rule, _message(Auto_Submitted="auto-replied"), {}) is False

    def test_a_negated_unknown_field_is_true(self):
        """An unknown field is the same "missing" case as an absent header."""
        rule = make_rule("no_such_field", "equals", "x", negate=True)

        assert evaluate_rule(rule, _message(), {}) is True


def _attachments(*names: str) -> dict:
    return {
        "attachments": [
            {"filename": name, "content_type": "application/octet-stream"} for name in names
        ]
    }


class TestMultiValuedNegation:
    def test_positive_matches_when_any_part_matches(self):
        rule = make_rule("attachment_names", "ends_with", ".exe")

        assert evaluate_rule(rule, _message(), _attachments("a.pdf", "b.exe")) is True

    def test_negated_is_false_when_any_part_matches(self):
        """Not "some part does not match": a.pdf not ending in .exe must not satisfy it."""
        rule = make_rule("attachment_names", "ends_with", ".exe", negate=True)

        assert evaluate_rule(rule, _message(), _attachments("a.pdf", "b.exe")) is False

    def test_negated_is_true_when_no_part_matches(self):
        rule = make_rule("attachment_names", "ends_with", ".exe", negate=True)

        assert evaluate_rule(rule, _message(), _attachments("a.pdf", "c.txt")) is True

    def test_negated_is_true_without_parts(self):
        rule = make_rule("attachment_types", "contains", "pdf", negate=True)

        assert evaluate_rule(rule, _message(), _attachments()) is True


class TestLoopGuard:
    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            ({"From": "noreply@example.com", "Auto_Submitted": "auto-generated"}, True),
            ({"From": "support@example.com", "Auto_Submitted": "auto-replied"}, True),
            ({"From": "noreply@example.com", "Auto_Submitted": "no"}, False),
            ({"From": "noreply@example.com"}, False),
            ({"From": "alice@example.com", "Auto_Submitted": "auto-generated"}, False),
        ],
    )
    def test_loop_guard(self, headers: dict[str, str], expected: bool):
        rule = make_compound_rule("all", LOOP_GUARD)

        assert evaluate_rule(rule, _message(**headers), {}) is expected


class TestDecisionLog:
    def test_names_the_deciding_condition(self, caplog: pytest.LogCaptureFixture):
        rule = make_compound_rule("all", LOOP_GUARD)
        message = _message(From="noreply@example.com", Auto_Submitted="no")

        with caplog.at_level(logging.DEBUG, logger="fastsmtp.rules.engine"):
            evaluate_rule(rule, message, {})

        assert f"Rule {rule.id} did not match" in caplog.text
        assert "conditions[2]" in caplog.text
        assert "NOT header:Auto-Submitted equals" in caplog.text

    def test_a_match_under_all_names_the_last_condition(self, caplog: pytest.LogCaptureFixture):
        rule = make_compound_rule("all", LOOP_GUARD)
        message = _message(From="noreply@example.com", Auto_Submitted="auto-generated")

        with caplog.at_level(logging.DEBUG, logger="fastsmtp.rules.engine"):
            evaluate_rule(rule, message, {})

        assert f"Rule {rule.id} matched" in caplog.text
        assert "conditions[2]" in caplog.text


class TestSchemas:
    ACTION = {"action": "drop"}

    def test_create_accepts_conditions(self):
        data = RuleCreate.model_validate(
            {
                **self.ACTION,
                "match": "any",
                "conditions": [
                    {"field": "subject", "operator": "contains", "value": "x"},
                    {"field": "header:X-Foo", "operator": "exists", "negate": True},
                ],
            }
        )

        assert data.match == "any"
        assert [c.negate for c in data.conditions] == [False, True]
        assert data.conditions[1].value == ""

    def test_match_defaults_to_all(self):
        data = RuleCreate.model_validate(
            {**self.ACTION, "conditions": [{"field": "subject", "operator": "exists"}]}
        )

        assert data.match == "all"

    def test_create_maps_the_legacy_shape_to_one_condition(self):
        data = RuleCreate.model_validate(
            {
                **self.ACTION,
                "field": "from",
                "operator": "equals",
                "value": "a@b.c",
                "case_sensitive": True,
            }
        )

        assert len(data.conditions) == 1
        condition = data.conditions[0]
        assert (condition.field, condition.operator, condition.value) == ("from", "equals", "a@b.c")
        assert condition.case_sensitive is True
        assert condition.negate is False

    def test_both_shapes_are_refused(self):
        with pytest.raises(ValidationError, match="not both"):
            RuleCreate.model_validate(
                {
                    **self.ACTION,
                    "field": "from",
                    "operator": "equals",
                    "value": "a@b.c",
                    "conditions": [{"field": "subject", "operator": "exists"}],
                }
            )

    def test_neither_shape_is_refused(self):
        with pytest.raises(ValidationError, match="conditions"):
            RuleCreate.model_validate(self.ACTION)

    def test_an_empty_list_is_refused(self):
        with pytest.raises(ValidationError, match="at least 1"):
            RuleCreate.model_validate({**self.ACTION, "conditions": []})

    def test_over_the_limit_is_refused(self):
        conditions = [{"field": "subject", "operator": "exists"}] * (MAX_RULE_CONDITIONS + 1)

        with pytest.raises(ValidationError, match=f"at most {MAX_RULE_CONDITIONS}"):
            RuleCreate.model_validate({**self.ACTION, "conditions": conditions})

    def test_the_limit_itself_is_accepted(self):
        conditions = [{"field": "subject", "operator": "exists"}] * MAX_RULE_CONDITIONS

        data = RuleCreate.model_validate({**self.ACTION, "conditions": conditions})

        assert len(data.conditions) == MAX_RULE_CONDITIONS

    def test_an_unknown_match_mode_is_refused(self):
        with pytest.raises(ValidationError):
            RuleCreate.model_validate(
                {
                    **self.ACTION,
                    "match": "none",
                    "conditions": [{"field": "subject", "operator": "exists"}],
                }
            )

    def test_regex_is_validated_per_condition(self):
        with pytest.raises(ValidationError) as excinfo:
            RuleCreate.model_validate(
                {
                    **self.ACTION,
                    "conditions": [
                        {"field": "subject", "operator": "regex", "value": "^ok$"},
                        {"field": "from", "operator": "regex", "value": r"(a)\1"},
                    ],
                }
            )

        (error,) = excinfo.value.errors()
        assert error["loc"][:2] == ("conditions", 1)
        assert "Invalid regex pattern" in error["msg"]

    def test_condition_fields_and_operators_are_validated(self):
        with pytest.raises(ValidationError, match="Invalid field"):
            RuleCreate.model_validate(
                {**self.ACTION, "conditions": [{"field": "nope", "operator": "exists"}]}
            )
        with pytest.raises(ValidationError, match="Invalid operator"):
            RuleCreate.model_validate(
                {**self.ACTION, "conditions": [{"field": "subject", "operator": "nope"}]}
            )

    def test_update_refuses_both_shapes(self):
        with pytest.raises(ValidationError, match="not both"):
            RuleUpdate.model_validate(
                {"value": "x", "conditions": [{"field": "subject", "operator": "exists"}]}
            )

    @pytest.mark.parametrize("operator", ["equals", "contains", "starts_with", "regex"])
    def test_a_missing_value_is_refused_except_for_exists(self, operator: str):
        """``contains ""`` matches everything, so a forgotten value would drop all mail."""
        with pytest.raises(ValidationError, match="non-empty value"):
            RuleCreate(field="from", operator=operator, action="drop")
        with pytest.raises(ValidationError, match="non-empty value"):
            RuleCreate(conditions=[{"field": "from", "operator": operator}])

    def test_exists_needs_no_value(self):
        rule = RuleCreate(conditions=[{"field": "header:X-Foo", "operator": "exists"}])
        assert rule.conditions is not None
        assert rule.conditions[0].value == ""

    def test_update_refuses_an_empty_list(self):
        with pytest.raises(ValidationError, match="at least 1"):
            RuleUpdate.model_validate({"conditions": []})


def _response_for(rule: Rule) -> dict:
    """Serialise a transient rule the way the API would."""
    rule.id = uuid.uuid4()
    rule.ruleset_id = uuid.uuid4()
    rule.order = 0
    rule.action = "forward"
    rule.add_tags = []
    rule.preserve_raw = False
    rule.created_at = rule.updated_at = datetime(2026, 1, 1)
    return RuleResponse.model_validate(rule).model_dump(mode="json")


class TestLegacyEcho:
    def test_a_single_plain_condition_echoes_the_flat_fields(self):
        body = _response_for(make_rule("from", "equals", "a@b.c", case_sensitive=True))

        assert body["match"] == "all"
        assert body["conditions"] == [
            {
                "field": "from",
                "operator": "equals",
                "value": "a@b.c",
                "case_sensitive": True,
                "negate": False,
            }
        ]
        assert (body["field"], body["operator"], body["value"]) == ("from", "equals", "a@b.c")
        assert body["case_sensitive"] is True

    @pytest.mark.parametrize(
        "rule",
        [
            pytest.param(make_rule("from", "equals", "a@b.c", negate=True), id="negated"),
            pytest.param(
                make_compound_rule("all", [("from", "exists"), ("subject", "exists")]),
                id="two-conditions",
            ),
        ],
    )
    def test_a_rule_the_flat_fields_cannot_describe_echoes_null(self, rule: Rule):
        body = _response_for(rule)

        assert body["field"] is None
        assert body["operator"] is None
        assert body["value"] is None
        assert body["case_sensitive"] is None


def test_openapi_marks_the_flat_fields_deprecated():
    from fastsmtp.config import Settings
    from fastsmtp.main import create_app

    app = create_app(Settings(database_url="sqlite+aiosqlite:///:memory:", root_api_key="x"))
    schemas = app.openapi()["components"]["schemas"]

    for name in ("RuleCreate", "RuleUpdate", "RuleResponse"):
        properties = schemas[name]["properties"]
        for flat in ("field", "operator", "value", "case_sensitive"):
            assert properties[flat].get("deprecated") is True, (name, flat)
        assert properties["conditions"].get("deprecated") is not True
    assert "conditions" in schemas["RuleResponse"]["required"]


class TestApi:
    @pytest_asyncio.fixture
    async def ruleset(self, test_session: AsyncSession) -> RuleSet:
        domain = Domain(domain_name="conditions-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()
        ruleset = RuleSet(domain_id=domain.id, name="Conditions", priority=0)
        test_session.add(ruleset)
        await test_session.commit()
        await test_session.refresh(ruleset)
        return ruleset

    @staticmethod
    def _rules_url(ruleset: RuleSet) -> str:
        return f"/api/v1/domains/{ruleset.domain_id}/rulesets/{ruleset.id}/rules"

    @staticmethod
    def _rule_url(ruleset: RuleSet, rule_id: str) -> str:
        return f"/api/v1/domains/{ruleset.domain_id}/rules/{rule_id}"

    async def _create(self, client: AsyncClient, ruleset: RuleSet, body: dict) -> dict:
        response = await client.post(self._rules_url(ruleset), json=body)
        assert response.status_code == 201, response.json()
        return response.json()

    async def test_create_and_read_back_conditions(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        conditions = [
            {"field": f, "operator": o, "value": v, "case_sensitive": c, "negate": n}
            for f, o, v, c, n in [
                ("from", "regex", r"^(noreply|support)@example\.com$", False, False),
                ("header:Auto-Submitted", "exists", "", False, False),
                ("header:Auto-Submitted", "equals", "no", True, True),
            ]
        ]
        created = await self._create(
            auth_client, ruleset, {"match": "all", "conditions": conditions, "action": "drop"}
        )

        assert created["match"] == "all"
        assert created["conditions"] == conditions
        assert created["field"] is None

        detail = await auth_client.get(f"/api/v1/domains/{ruleset.domain_id}/rulesets/{ruleset.id}")
        (rule,) = detail.json()["rules"]
        assert rule["conditions"] == conditions

    async def test_legacy_shape_round_trips(self, auth_client: AsyncClient, ruleset: RuleSet):
        created = await self._create(
            auth_client,
            ruleset,
            {"field": "subject", "operator": "contains", "value": "x", "action": "tag"},
        )

        assert (created["field"], created["operator"], created["value"]) == (
            "subject",
            "contains",
            "x",
        )
        assert created["case_sensitive"] is False
        assert created["conditions"] == [
            {
                "field": "subject",
                "operator": "contains",
                "value": "x",
                "case_sensitive": False,
                "negate": False,
            }
        ]

    async def test_both_shapes_are_a_422(self, auth_client: AsyncClient, ruleset: RuleSet):
        response = await auth_client.post(
            self._rules_url(ruleset),
            json={
                "field": "subject",
                "operator": "contains",
                "value": "x",
                "conditions": [{"field": "subject", "operator": "exists"}],
            },
        )

        assert response.status_code == 422

    async def test_invalid_regex_in_a_condition_is_a_422(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        response = await auth_client.post(
            self._rules_url(ruleset),
            json={"conditions": [{"field": "subject", "operator": "regex", "value": "(?=x)"}]},
        )

        assert response.status_code == 422
        (error,) = response.json()["detail"]
        assert error["loc"][:3] == ["body", "conditions", 0]
        assert "Invalid regex pattern" in error["msg"]

    async def test_update_replaces_the_condition_list(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        created = await self._create(
            auth_client, ruleset, {"field": "subject", "operator": "contains", "value": "x"}
        )
        new = [
            {"field": "from", "operator": "contains", "value": "a"},
            {"field": "to", "operator": "contains", "value": "b", "negate": True},
        ]

        response = await auth_client.put(
            self._rule_url(ruleset, created["id"]), json={"match": "any", "conditions": new}
        )

        assert response.status_code == 200, response.json()
        body = response.json()
        assert body["match"] == "any"
        assert [(c["field"], c["negate"]) for c in body["conditions"]] == [
            ("from", False),
            ("to", True),
        ]
        assert body["field"] is None

    async def test_legacy_partial_update_edits_the_sole_condition(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        created = await self._create(
            auth_client, ruleset, {"field": "subject", "operator": "contains", "value": "x"}
        )

        response = await auth_client.put(
            self._rule_url(ruleset, created["id"]), json={"value": "y"}
        )

        assert response.status_code == 200, response.json()
        assert response.json()["conditions"][0]["value"] == "y"
        assert response.json()["conditions"][0]["field"] == "subject"

    async def test_legacy_update_to_an_empty_value_is_a_422(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        created = await self._create(
            auth_client, ruleset, {"field": "subject", "operator": "contains", "value": "x"}
        )

        response = await auth_client.put(self._rule_url(ruleset, created["id"]), json={"value": ""})

        assert response.status_code == 422, response.json()

    @pytest.mark.parametrize("field", ["action", "add_tags", "preserve_raw", "match"])
    async def test_an_explicit_null_on_a_required_field_leaves_it_unchanged(
        self, auth_client: AsyncClient, ruleset: RuleSet, field: str
    ):
        created = await self._create(
            auth_client,
            ruleset,
            {"field": "subject", "operator": "contains", "value": "x", "action": "drop"},
        )

        response = await auth_client.put(self._rule_url(ruleset, created["id"]), json={field: None})

        assert response.status_code == 200, response.json()
        assert response.json()[field] == created[field]

    async def test_legacy_update_of_a_compound_rule_is_a_422(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        created = await self._create(
            auth_client,
            ruleset,
            {
                "conditions": [
                    {"field": "from", "operator": "exists"},
                    {"field": "to", "operator": "exists"},
                ]
            },
        )

        response = await auth_client.put(
            self._rule_url(ruleset, created["id"]), json={"value": "y"}
        )

        assert response.status_code == 422
        assert "conditions" in response.json()["detail"]

    async def test_legacy_update_of_a_negated_rule_is_a_422(
        self, auth_client: AsyncClient, ruleset: RuleSet
    ):
        created = await self._create(
            auth_client,
            ruleset,
            {"conditions": [{"field": "from", "operator": "exists", "negate": True}]},
        )

        response = await auth_client.put(
            self._rule_url(ruleset, created["id"]), json={"operator": "contains"}
        )

        assert response.status_code == 422

    async def test_update_both_shapes_is_a_422(self, auth_client: AsyncClient, ruleset: RuleSet):
        created = await self._create(
            auth_client, ruleset, {"field": "subject", "operator": "contains", "value": "x"}
        )

        response = await auth_client.put(
            self._rule_url(ruleset, created["id"]),
            json={"value": "y", "conditions": [{"field": "subject", "operator": "exists"}]},
        )

        assert response.status_code == 422

    async def test_deleting_a_rule_deletes_its_conditions(
        self, auth_client: AsyncClient, ruleset: RuleSet, test_session: AsyncSession
    ):
        from fastsmtp.db.models import RuleCondition
        from sqlalchemy import func, select

        created = await self._create(
            auth_client,
            ruleset,
            {
                "conditions": [
                    {"field": "from", "operator": "exists"},
                    {"field": "to", "operator": "exists"},
                ]
            },
        )

        response = await auth_client.delete(self._rule_url(ruleset, created["id"]))
        assert response.status_code == 200

        count = await test_session.scalar(select(func.count()).select_from(RuleCondition))
        assert count == 0


class TestEvaluateRulesFromTheDatabase:
    async def test_loop_guard_drops_only_the_loop(self, test_session: AsyncSession):
        domain = Domain(domain_name="loop-guard.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()
        ruleset = RuleSet(domain_id=domain.id, name="Own automated mail", priority=100)
        test_session.add(ruleset)
        await test_session.flush()
        test_session.add(
            make_compound_rule("all", LOOP_GUARD, ruleset_id=ruleset.id, order=0, action="drop")
        )
        await test_session.commit()

        loop = _message(From="noreply@example.com", Auto_Submitted="auto-generated")
        human = _message(From="noreply@example.com")

        assert (await evaluate_rules(test_session, domain, loop, {})).should_drop
        assert not (await evaluate_rules(test_session, domain, human, {})).should_drop


def test_make_condition_defaults():
    """Guard the helper the rest of the suite leans on."""
    condition = make_condition("subject", "exists")

    assert (condition.value, condition.case_sensitive, condition.negate) == ("", False, False)
