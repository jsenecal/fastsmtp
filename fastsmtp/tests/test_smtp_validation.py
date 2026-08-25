"""Tests for SMTP email authentication validation to improve coverage."""

import asyncio

import pytest
from fastsmtp.db.models import Domain
from fastsmtp.smtp.validation import (
    RESULT_FAIL,
    RESULT_NONE,
    RESULT_PASS,
    RESULT_PERMERROR,
    RESULT_SOFTFAIL,
    RESULT_TEMPERROR,
    EffectiveAuthPolicy,
    EmailAuthResult,
    _verify_dkim_sync,
    _verify_spf_sync,
    resolve_auth_policy,
    validate_email_auth,
    verify_dkim,
    verify_spf,
)


class TestEmailAuthResult:
    """Tests for EmailAuthResult dataclass."""

    def test_dkim_passed_true(self):
        """Test dkim_passed returns True when DKIM passed."""
        result = EmailAuthResult(
            dkim_result=RESULT_PASS,
            dkim_domain="example.com",
            dkim_selector="selector1",
            spf_result=RESULT_NONE,
            spf_domain=None,
            client_ip="192.168.1.1",
        )
        assert result.dkim_passed is True

    def test_dkim_passed_false(self):
        """Test dkim_passed returns False when DKIM failed."""
        result = EmailAuthResult(
            dkim_result=RESULT_FAIL,
            dkim_domain="example.com",
            dkim_selector="selector1",
            spf_result=RESULT_NONE,
            spf_domain=None,
            client_ip="192.168.1.1",
        )
        assert result.dkim_passed is False

    def test_spf_passed_true(self):
        """Test spf_passed returns True when SPF passed."""
        result = EmailAuthResult(
            dkim_result=RESULT_NONE,
            dkim_domain=None,
            dkim_selector=None,
            spf_result=RESULT_PASS,
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        assert result.spf_passed is True

    def test_spf_passed_false(self):
        """Test spf_passed returns False when SPF not passed."""
        result = EmailAuthResult(
            dkim_result=RESULT_NONE,
            dkim_domain=None,
            dkim_selector=None,
            spf_result=RESULT_FAIL,
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        assert result.spf_passed is False

    def test_spf_failed_true(self):
        """Test spf_failed returns True only for explicit fail."""
        result = EmailAuthResult(
            dkim_result=RESULT_NONE,
            dkim_domain=None,
            dkim_selector=None,
            spf_result=RESULT_FAIL,
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        assert result.spf_failed is True

    def test_spf_failed_false_for_softfail(self):
        """Test spf_failed returns False for softfail."""
        result = EmailAuthResult(
            dkim_result=RESULT_NONE,
            dkim_domain=None,
            dkim_selector=None,
            spf_result="softfail",
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        assert result.spf_failed is False


class TestVerifyDKIM:
    """Tests for DKIM verification."""

    def test_verify_dkim_no_signature(self):
        """Test DKIM verification on message with no signature."""
        message = b"""From: sender@example.com
To: recipient@test.com
Subject: Test
Content-Type: text/plain

Test body.
"""
        result, domain, selector = _verify_dkim_sync(message)
        # Either NONE or FAIL depending on dkim library behavior
        assert result in (RESULT_NONE, RESULT_FAIL)

    def test_verify_dkim_invalid_message(self):
        """Test DKIM verification on invalid message."""
        message = b"invalid email content"
        result, domain, selector = _verify_dkim_sync(message)
        # Should return an error result
        assert result in (RESULT_NONE, RESULT_FAIL, RESULT_TEMPERROR, "permerror")

    @pytest.mark.asyncio
    async def test_verify_dkim_async(self):
        """Test async DKIM verification."""
        message = b"""From: sender@example.com
To: recipient@test.com
Subject: Test

Test body.
"""
        result, domain, selector = await verify_dkim(message)
        assert result in (RESULT_NONE, RESULT_FAIL)


class TestVerifySPF:
    """Tests for SPF verification."""

    def test_verify_spf_localhost(self):
        """Test SPF verification from localhost."""
        result, domain = _verify_spf_sync(
            client_ip="127.0.0.1",
            mail_from="test@localhost",
            helo="localhost",
        )
        # SPF result varies - could be none, neutral, or softfail for localhost
        assert result in (RESULT_NONE, "neutral", "softfail", RESULT_PASS)

    def test_verify_spf_no_domain(self):
        """Test SPF verification with helo as domain."""
        result, domain = _verify_spf_sync(
            client_ip="192.168.1.1",
            mail_from="",
            helo="mail.example.com",
        )
        assert domain == "mail.example.com"

    def test_verify_spf_with_email(self):
        """Test SPF verification extracts domain from email."""
        result, domain = _verify_spf_sync(
            client_ip="192.168.1.1",
            mail_from="sender@example.com",
            helo="mail.example.com",
        )
        assert domain == "example.com"

    @pytest.mark.asyncio
    async def test_verify_spf_async(self):
        """Test async SPF verification."""
        result, domain = await verify_spf(
            client_ip="127.0.0.1",
            mail_from="test@localhost",
            helo="localhost",
        )
        assert result in (RESULT_NONE, "neutral", "softfail", RESULT_PASS)


class TestValidateEmailAuth:
    """Tests for combined email auth validation."""

    @pytest.mark.asyncio
    async def test_validate_email_auth_both_enabled(self):
        """Test validation with both DKIM and SPF enabled."""
        message = b"""From: sender@example.com
To: recipient@test.com
Subject: Test

Test body.
"""
        result = await validate_email_auth(
            message=message,
            client_ip="127.0.0.1",
            mail_from="sender@example.com",
            helo="localhost",
            verify_dkim_enabled=True,
            verify_spf_enabled=True,
        )

        assert isinstance(result, EmailAuthResult)
        assert result.client_ip == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_validate_email_auth_dkim_disabled(self):
        """Test validation with DKIM disabled."""
        message = b"""From: sender@example.com
To: recipient@test.com
Subject: Test

Test body.
"""
        result = await validate_email_auth(
            message=message,
            client_ip="127.0.0.1",
            mail_from="sender@example.com",
            helo="localhost",
            verify_dkim_enabled=False,
            verify_spf_enabled=True,
        )

        assert isinstance(result, EmailAuthResult)
        assert result.dkim_result == RESULT_NONE

    @pytest.mark.asyncio
    async def test_validate_email_auth_spf_disabled(self):
        """Test validation with SPF disabled."""
        message = b"""From: sender@example.com
To: recipient@test.com
Subject: Test

Test body.
"""
        result = await validate_email_auth(
            message=message,
            client_ip="127.0.0.1",
            mail_from="sender@example.com",
            helo="localhost",
            verify_dkim_enabled=True,
            verify_spf_enabled=False,
        )

        assert isinstance(result, EmailAuthResult)
        assert result.spf_result == RESULT_NONE

    @pytest.mark.asyncio
    async def test_validate_email_auth_both_disabled(self):
        """Test validation with both disabled."""
        message = b"""From: sender@example.com
To: recipient@test.com
Subject: Test

Test body.
"""
        result = await validate_email_auth(
            message=message,
            client_ip="127.0.0.1",
            mail_from="sender@example.com",
            helo="localhost",
            verify_dkim_enabled=False,
            verify_spf_enabled=False,
        )

        assert isinstance(result, EmailAuthResult)
        assert result.dkim_result == RESULT_NONE
        assert result.spf_result == RESULT_NONE

    @pytest.mark.asyncio
    async def test_validate_email_auth_dkim_exception_is_temperror(self, monkeypatch):
        """A DKIM failure in the parallel path degrades to temperror, SPF unaffected."""

        async def boom(_message):
            raise RuntimeError("dkim exploded")

        async def ok_spf(_client_ip, _mail_from, _helo):
            return RESULT_PASS, "example.com"

        monkeypatch.setattr("fastsmtp.smtp.validation.verify_dkim", boom)
        monkeypatch.setattr("fastsmtp.smtp.validation.verify_spf", ok_spf)

        result = await validate_email_auth(
            message=b"From: sender@example.com\r\n\r\nbody",
            client_ip="127.0.0.1",
            mail_from="sender@example.com",
            helo="localhost",
        )

        assert result.dkim_result == RESULT_TEMPERROR
        assert result.dkim_domain is None
        assert result.dkim_selector is None
        assert result.spf_result == RESULT_PASS
        assert result.spf_domain == "example.com"

    @pytest.mark.asyncio
    async def test_validate_email_auth_spf_exception_is_temperror(self, monkeypatch):
        """An SPF failure in the parallel path degrades to temperror, DKIM unaffected."""

        async def ok_dkim(_message):
            return RESULT_PASS, "example.com", "selector1"

        async def boom(_client_ip, _mail_from, _helo):
            raise RuntimeError("spf exploded")

        monkeypatch.setattr("fastsmtp.smtp.validation.verify_dkim", ok_dkim)
        monkeypatch.setattr("fastsmtp.smtp.validation.verify_spf", boom)

        result = await validate_email_auth(
            message=b"From: sender@example.com\r\n\r\nbody",
            client_ip="127.0.0.1",
            mail_from="sender@example.com",
            helo="localhost",
        )

        assert result.dkim_result == RESULT_PASS
        assert result.dkim_domain == "example.com"
        assert result.dkim_selector == "selector1"
        assert result.spf_result == RESULT_TEMPERROR
        assert result.spf_domain is None

    @pytest.mark.asyncio
    async def test_validate_email_auth_propagates_cancellation(self, monkeypatch):
        """Cancellation must propagate, not be unpacked as if it were a result.

        ``asyncio.gather(..., return_exceptions=True)`` hands back a
        ``CancelledError`` *instance* for a cancelled child instead of raising,
        so the parallel path has to recognise ``BaseException`` and not just
        ``Exception``. The single-validator paths already let it through via
        ``except Exception``.
        """

        async def cancelled(_message):
            raise asyncio.CancelledError

        async def ok_spf(_client_ip, _mail_from, _helo):
            return RESULT_PASS, "example.com"

        monkeypatch.setattr("fastsmtp.smtp.validation.verify_dkim", cancelled)
        monkeypatch.setattr("fastsmtp.smtp.validation.verify_spf", ok_spf)

        with pytest.raises(asyncio.CancelledError):
            await validate_email_auth(
                message=b"From: sender@example.com\r\n\r\nbody",
                client_ip="127.0.0.1",
                mail_from="sender@example.com",
                helo="localhost",
            )


class TestDKIMEdgeCases:
    """Tests for DKIM edge cases."""

    def test_verify_dkim_valid_signature_format(self):
        """Test DKIM with valid signature format but invalid signature."""
        # A message with DKIM-Signature header but invalid signature
        message = b"""DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1;
\tc=relaxed/relaxed; q=dns/txt; t=1234567890;
\tbh=ABCD1234567890;
\th=From:To:Subject;
\tb=InvalidSignatureData1234567890==
From: sender@example.com
To: recipient@test.com
Subject: Test

Test body.
"""
        result, domain, selector = _verify_dkim_sync(message)
        # Should fail or return error due to invalid signature
        assert result in (RESULT_FAIL, RESULT_PERMERROR, RESULT_NONE)


class TestSPFEdgeCases:
    """Tests for SPF edge cases."""

    def test_verify_spf_empty_mail_from(self):
        """Test SPF verification with empty MAIL FROM uses helo."""
        result, domain = _verify_spf_sync(
            client_ip="192.168.1.1",
            mail_from="",
            helo="mail.example.com",
        )
        assert domain == "mail.example.com"

    def test_verify_spf_mail_from_no_at(self):
        """Test SPF verification with malformed MAIL FROM."""
        result, domain = _verify_spf_sync(
            client_ip="192.168.1.1",
            mail_from="invalid-no-at-sign",
            helo="mail.example.com",
        )
        # Should use helo as domain since mail_from has no @
        assert domain == "mail.example.com"


FLAGS = ("verify_dkim", "verify_spf", "reject_dkim_fail", "reject_spf_fail")


def _auth_result(dkim: str = RESULT_NONE, spf: str = RESULT_NONE) -> EmailAuthResult:
    return EmailAuthResult(
        dkim_result=dkim,
        dkim_domain=None,
        dkim_selector=None,
        spf_result=spf,
        spf_domain=None,
        client_ip="203.0.113.10",
    )


def _policy(make_smtp_settings, **overrides: bool) -> EffectiveAuthPolicy:
    """The policy of a domain carrying ``overrides``, over default settings."""
    return resolve_auth_policy(Domain(domain_name="policy.test", **overrides), make_smtp_settings())


class TestResolveAuthPolicy:
    """Tests for resolving a domain's tri-state auth columns against the globals."""

    @pytest.mark.parametrize("global_value", [True, False])
    @pytest.mark.parametrize("flag", FLAGS)
    def test_null_column_inherits_the_global_setting(
        self, make_smtp_settings, flag: str, global_value: bool
    ):
        """A column left NULL follows the server-wide setting, whatever it is."""
        settings = make_smtp_settings(**{f"smtp_{flag}": global_value})

        policy = resolve_auth_policy(Domain(domain_name="inherit.test"), settings)

        assert getattr(policy, flag) is global_value

    @pytest.mark.parametrize("override", [True, False])
    @pytest.mark.parametrize("flag", FLAGS)
    def test_column_overrides_the_global_setting(
        self, make_smtp_settings, flag: str, override: bool
    ):
        """A column that is set wins over the global setting in both directions."""
        settings = make_smtp_settings(**{f"smtp_{flag}": not override})

        policy = resolve_auth_policy(
            Domain(domain_name="override.test", **{flag: override}), settings
        )

        assert getattr(policy, flag) is override

    def test_flags_are_resolved_independently(self, make_smtp_settings):
        """Overriding one flag leaves the other three inheriting."""
        settings = make_smtp_settings(
            smtp_verify_dkim=True,
            smtp_verify_spf=True,
            smtp_reject_dkim_fail=False,
            smtp_reject_spf_fail=False,
        )

        policy = resolve_auth_policy(
            Domain(domain_name="mixed.test", verify_spf=False, reject_dkim_fail=True), settings
        )

        assert policy.verify_dkim is True
        assert policy.verify_spf is False
        assert policy.reject_dkim_fail is True
        assert policy.reject_spf_fail is False

    def test_no_domain_is_the_global_policy(self, make_smtp_settings):
        """An address with no configured domain keeps the server-wide settings."""
        settings = make_smtp_settings(
            smtp_verify_dkim=True,
            smtp_verify_spf=False,
            smtp_reject_dkim_fail=True,
            smtp_reject_spf_fail=False,
        )

        policy = resolve_auth_policy(None, settings)

        assert policy.verify_dkim is True
        assert policy.verify_spf is False
        assert policy.reject_dkim_fail is True
        assert policy.reject_spf_fail is False


class TestMaskedResult:
    """What one recipient domain is shown of the message-level result."""

    @staticmethod
    def _both_failed() -> EmailAuthResult:
        return EmailAuthResult(
            dkim_result=RESULT_FAIL,
            dkim_domain="signer.test",
            dkim_selector="s1",
            spf_result=RESULT_FAIL,
            spf_domain="envelope.test",
            client_ip="203.0.113.10",
        )

    def test_a_domain_verifying_both_sees_the_result_itself(self, make_smtp_settings):
        """Nothing is copied, and nothing is blanked, for a domain that asked for both."""
        policy = _policy(make_smtp_settings, verify_dkim=True, verify_spf=True)
        auth_result = self._both_failed()

        assert policy.masked(auth_result) is auth_result

    def test_an_unverified_mechanism_reads_as_not_checked(self, make_smtp_settings):
        """Everything DKIM produced is blanked for a domain that opted out of it."""
        policy = _policy(make_smtp_settings, verify_dkim=False, verify_spf=True)

        masked = policy.masked(self._both_failed())

        assert masked.dkim_result == RESULT_NONE
        assert masked.dkim_domain is None
        assert masked.dkim_selector is None
        assert masked.spf_result == RESULT_FAIL
        assert masked.spf_domain == "envelope.test"

    def test_masking_spf_leaves_dkim_alone(self, make_smtp_settings):
        policy = _policy(make_smtp_settings, verify_dkim=True, verify_spf=False)

        masked = policy.masked(self._both_failed())

        assert masked.dkim_result == RESULT_FAIL
        assert masked.dkim_domain == "signer.test"
        assert masked.spf_result == RESULT_NONE
        assert masked.spf_domain is None

    def test_the_message_level_result_is_not_mutated(self, make_smtp_settings):
        """One recipient's view must not become the next recipient's."""
        policy = _policy(make_smtp_settings, verify_dkim=False, verify_spf=False)
        auth_result = self._both_failed()

        policy.masked(auth_result)

        assert auth_result.dkim_result == RESULT_FAIL
        assert auth_result.spf_result == RESULT_FAIL

    def test_the_client_ip_survives_masking(self, make_smtp_settings):
        policy = _policy(make_smtp_settings, verify_dkim=False, verify_spf=False)

        assert policy.masked(self._both_failed()).client_ip == "203.0.113.10"


class TestRefusedMechanism:
    """Tests for the per-recipient refusal decision."""

    def test_verified_and_rejecting_refuses_a_failure(self, make_smtp_settings):
        """A domain that verifies DKIM and rejects failures refuses a fail."""
        policy = _policy(make_smtp_settings, verify_dkim=True, reject_dkim_fail=True)

        assert policy.refused_mechanism(_auth_result(dkim=RESULT_FAIL)) == "DKIM"

    def test_unverified_mechanism_cannot_refuse(self, make_smtp_settings):
        """reject_dkim_fail is inert while the domain does not verify DKIM."""
        policy = _policy(make_smtp_settings, verify_dkim=False, reject_dkim_fail=True)

        assert policy.refused_mechanism(_auth_result(dkim=RESULT_FAIL)) is None

    def test_verified_without_rejecting_does_not_refuse(self, make_smtp_settings):
        """Verifying a mechanism does not by itself refuse anything."""
        policy = _policy(make_smtp_settings, verify_dkim=True, reject_dkim_fail=False)

        assert policy.refused_mechanism(_auth_result(dkim=RESULT_FAIL)) is None

    @pytest.mark.parametrize("spf_result", [RESULT_SOFTFAIL, RESULT_NONE, RESULT_PASS])
    def test_only_a_hard_fail_refuses(self, make_smtp_settings, spf_result: str):
        """softfail, none and pass are not failures."""
        policy = _policy(make_smtp_settings, verify_spf=True, reject_spf_fail=True)

        assert policy.refused_mechanism(_auth_result(spf=spf_result)) is None

    def test_spf_refusal_is_named(self, make_smtp_settings):
        """An SPF-only refusal names SPF."""
        policy = _policy(make_smtp_settings, verify_spf=True, reject_spf_fail=True)

        assert policy.refused_mechanism(_auth_result(spf=RESULT_FAIL)) == "SPF"

    def test_dkim_is_named_when_both_mechanisms_refuse(self, make_smtp_settings):
        """With both failing, DKIM is the mechanism reported, as before."""
        policy = _policy(
            make_smtp_settings,
            verify_dkim=True,
            reject_dkim_fail=True,
            verify_spf=True,
            reject_spf_fail=True,
        )

        assert policy.refused_mechanism(_auth_result(dkim=RESULT_FAIL, spf=RESULT_FAIL)) == "DKIM"
