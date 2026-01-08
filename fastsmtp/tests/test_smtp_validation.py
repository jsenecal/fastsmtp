"""Tests for SMTP email authentication validation to improve coverage."""

import pytest

from fastsmtp.smtp.validation import (
    RESULT_FAIL,
    RESULT_NONE,
    RESULT_PASS,
    RESULT_PERMERROR,
    RESULT_TEMPERROR,
    EmailAuthResult,
    _verify_dkim_sync,
    _verify_spf_sync,
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
