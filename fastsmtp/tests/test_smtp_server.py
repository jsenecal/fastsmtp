"""Tests for SMTP server functionality."""

from email import message_from_bytes

import pytest
import pytest_asyncio
from fastsmtp.db.models import Domain, Recipient
from fastsmtp.smtp.server import (
    extract_email_payload,
    find_recipient_for_address,
    lookup_recipient,
)
from fastsmtp.smtp.validation import (
    RESULT_FAIL,
    RESULT_NONE,
    RESULT_PASS,
    RESULT_SOFTFAIL,
    EmailAuthResult,
)
from sqlalchemy.ext.asyncio import AsyncSession


class TestExtractEmailPayload:
    """Tests for email payload extraction."""

    @pytest.mark.asyncio
    async def test_extract_simple_email(self, sample_email_content: bytes):
        """Test extracting payload from simple email."""
        message = message_from_bytes(sample_email_content)

        class MockEnvelope:
            mail_from = "sender@example.com"
            rcpt_tos = ["recipient@test.com"]

        payload = await extract_email_payload(message, MockEnvelope())

        assert payload["message_id"] == "<test123@example.com>"
        assert payload["from"] == "sender@example.com"
        assert payload["to"] == "recipient@test.com"
        assert payload["subject"] == "Test Email"
        assert "This is a test email body" in payload["body_text"]
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_extract_multipart_email(self, sample_multipart_email: bytes):
        """Test extracting payload from multipart email."""
        message = message_from_bytes(sample_multipart_email)

        class MockEnvelope:
            mail_from = "sender@example.com"
            rcpt_tos = ["recipient@test.com"]

        payload = await extract_email_payload(message, MockEnvelope())

        assert payload["message_id"] == "<test456@example.com>"
        assert payload["subject"] == "Test Multipart Email"
        assert "plain text version" in payload["body_text"]
        assert "HTML version" in payload["body_html"]
        assert payload["has_attachments"] is False

    @pytest.mark.asyncio
    async def test_extract_envelope_data(self, sample_email_content: bytes):
        """Test that envelope data is included."""
        message = message_from_bytes(sample_email_content)

        class MockEnvelope:
            mail_from = "bounce@example.com"
            rcpt_tos = ["recipient1@test.com", "recipient2@test.com"]

        payload = await extract_email_payload(message, MockEnvelope())

        assert payload["envelope_from"] == "bounce@example.com"
        assert "recipient1@test.com" in payload["envelope_to"]
        assert "recipient2@test.com" in payload["envelope_to"]

    @pytest.mark.asyncio
    async def test_extract_headers(self, sample_email_content: bytes):
        """Test that headers are included."""
        message = message_from_bytes(sample_email_content)

        class MockEnvelope:
            mail_from = "sender@example.com"
            rcpt_tos = ["recipient@test.com"]

        payload = await extract_email_payload(message, MockEnvelope())

        assert "headers" in payload
        assert payload["headers"]["From"] == "sender@example.com"
        assert payload["headers"]["Subject"] == "Test Email"


class TestLookupRecipient:
    """Tests for lookup_recipient function."""

    @pytest_asyncio.fixture
    async def test_domain_with_recipients(self, test_session: AsyncSession) -> Domain:
        """Create a test domain with recipients."""
        domain = Domain(domain_name="lookup-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        # Specific recipient
        r1 = Recipient(
            domain_id=domain.id,
            local_part="info",
            webhook_url="https://example.com/webhook",
            is_enabled=True,
        )
        # Catch-all recipient
        r2 = Recipient(
            domain_id=domain.id,
            local_part=None,
            webhook_url="https://example.com/catchall",
            is_enabled=True,
        )
        # Disabled recipient
        r3 = Recipient(
            domain_id=domain.id,
            local_part="disabled",
            webhook_url="https://example.com/disabled",
            is_enabled=False,
        )
        test_session.add_all([r1, r2, r3])
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_lookup_specific_recipient(
        self, test_session: AsyncSession, test_domain_with_recipients: Domain
    ):
        """Test looking up a specific recipient."""
        domain, recipient, error = await lookup_recipient("info@lookup-test.com", test_session)
        assert error is None
        assert domain is not None
        assert domain.domain_name == "lookup-test.com"
        assert recipient is not None
        assert recipient.local_part == "info"

    @pytest.mark.asyncio
    async def test_lookup_catchall_recipient(
        self, test_session: AsyncSession, test_domain_with_recipients: Domain
    ):
        """Test looking up a recipient that falls to catch-all."""
        domain, recipient, error = await lookup_recipient("unknown@lookup-test.com", test_session)
        assert error is None
        assert domain is not None
        assert recipient is not None
        assert recipient.local_part is None  # catch-all

    @pytest.mark.asyncio
    async def test_lookup_disabled_recipient_uses_catchall(
        self, test_session: AsyncSession, test_domain_with_recipients: Domain
    ):
        """Test looking up disabled recipient falls to catch-all."""
        domain, recipient, error = await lookup_recipient("disabled@lookup-test.com", test_session)
        assert error is None
        assert recipient is not None
        assert recipient.local_part is None  # catch-all

    @pytest.mark.asyncio
    async def test_lookup_unknown_domain(self, test_session: AsyncSession):
        """Test looking up address with unknown domain."""
        domain, recipient, error = await lookup_recipient("test@unknown-domain.com", test_session)
        assert domain is None
        assert recipient is None
        assert "not configured" in error

    @pytest.mark.asyncio
    async def test_lookup_invalid_address(self, test_session: AsyncSession):
        """Test looking up invalid address (no @)."""
        domain, recipient, error = await lookup_recipient("invalid-address", test_session)
        assert domain is None
        assert recipient is None
        assert "Invalid recipient" in error

    @pytest_asyncio.fixture
    async def test_domain_no_catchall(self, test_session: AsyncSession) -> Domain:
        """Create a domain without catch-all."""
        domain = Domain(domain_name="no-catchall.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        r = Recipient(
            domain_id=domain.id,
            local_part="specific",
            webhook_url="https://example.com/webhook",
            is_enabled=True,
        )
        test_session.add(r)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_lookup_no_matching_recipient(
        self, test_session: AsyncSession, test_domain_no_catchall: Domain
    ):
        """Test looking up address with no matching recipient and no catch-all."""
        domain, recipient, error = await lookup_recipient("unknown@no-catchall.com", test_session)
        assert domain is not None
        assert recipient is None
        assert "not found" in error

    @pytest.mark.asyncio
    async def test_lookup_case_insensitive(
        self, test_session: AsyncSession, test_domain_with_recipients: Domain
    ):
        """Test that recipient lookup is case-insensitive."""
        domain, recipient, error = await lookup_recipient("INFO@LOOKUP-TEST.COM", test_session)
        assert error is None
        assert recipient is not None
        assert recipient.local_part == "info"


class TestLookupRecipientSubaddress:
    """Tests for subaddress (plus-tag) recipient matching."""

    @pytest_asyncio.fixture
    async def subaddr_domain(self, test_session: AsyncSession) -> Domain:
        """Domain with a base recipient, an exact-plus recipient, and a catch-all."""
        domain = Domain(domain_name="subaddr-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        base = Recipient(
            domain_id=domain.id,
            local_part="support",
            webhook_url="https://example.com/support",
            is_enabled=True,
        )
        exact_plus = Recipient(
            domain_id=domain.id,
            local_part="support+x",
            webhook_url="https://example.com/support-x",
            is_enabled=True,
        )
        catchall = Recipient(
            domain_id=domain.id,
            local_part=None,
            webhook_url="https://example.com/catchall",
            is_enabled=True,
        )
        test_session.add_all([base, exact_plus, catchall])
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest_asyncio.fixture
    async def subaddr_domain_no_catchall(self, test_session: AsyncSession) -> Domain:
        """Domain with only a base recipient and no catch-all."""
        domain = Domain(domain_name="subaddr-nocatch.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        r = Recipient(
            domain_id=domain.id,
            local_part="support",
            webhook_url="https://example.com/support",
            is_enabled=True,
        )
        test_session.add(r)
        await test_session.commit()
        await test_session.refresh(domain)
        return domain

    @pytest.mark.asyncio
    async def test_plain_match_still_works(
        self, test_session: AsyncSession, subaddr_domain: Domain
    ):
        """A plain local part matches its recipient exactly."""
        domain, recipient, error = await lookup_recipient("support@subaddr-test.com", test_session)
        assert error is None
        assert recipient is not None
        assert recipient.local_part == "support"

    @pytest.mark.asyncio
    async def test_plus_tag_falls_back_to_base_recipient(
        self, test_session: AsyncSession, subaddr_domain_no_catchall: Domain
    ):
        """support+TICKET-123.tok@ routes to the 'support' recipient."""
        domain, recipient, error = await lookup_recipient(
            "support+TICKET-123.tok@subaddr-nocatch.com", test_session
        )
        assert error is None
        assert recipient is not None
        assert recipient.local_part == "support"

    @pytest.mark.asyncio
    async def test_plus_tag_base_match_wins_over_catchall(
        self, test_session: AsyncSession, subaddr_domain: Domain
    ):
        """The stripped base match is preferred over the catch-all."""
        domain, recipient, error = await lookup_recipient(
            "support+something@subaddr-test.com", test_session
        )
        assert error is None
        assert recipient is not None
        assert recipient.local_part == "support"

    @pytest.mark.asyncio
    async def test_exact_plus_recipient_wins_over_base(
        self, test_session: AsyncSession, subaddr_domain: Domain
    ):
        """A recipient literally named 'support+x' beats the 'support' fallback."""
        domain, recipient, error = await lookup_recipient(
            "support+x@subaddr-test.com", test_session
        )
        assert error is None
        assert recipient is not None
        assert recipient.local_part == "support+x"

    @pytest.mark.asyncio
    async def test_plus_tag_no_base_match_returns_error(
        self, test_session: AsyncSession, subaddr_domain_no_catchall: Domain
    ):
        """A plus-tagged address whose base has no recipient is rejected (550 path)."""
        domain, recipient, error = await lookup_recipient(
            "unknown+tag@subaddr-nocatch.com", test_session
        )
        assert domain is not None
        assert recipient is None
        assert error is not None
        assert "not found" in error

    @pytest.mark.asyncio
    async def test_plus_tag_no_base_match_uses_catchall(
        self, test_session: AsyncSession, subaddr_domain: Domain
    ):
        """Catch-all still applies when neither exact nor stripped base matches."""
        domain, recipient, error = await lookup_recipient(
            "unknown+tag@subaddr-test.com", test_session
        )
        assert error is None
        assert recipient is not None
        assert recipient.local_part is None  # catch-all

    @pytest.mark.asyncio
    async def test_plus_tag_case_insensitive(
        self, test_session: AsyncSession, subaddr_domain_no_catchall: Domain
    ):
        """Subaddress fallback is case-insensitive on the base local part."""
        domain, recipient, error = await lookup_recipient(
            "SUPPORT+Tag@SUBADDR-NOCATCH.COM", test_session
        )
        assert error is None
        assert recipient is not None
        assert recipient.local_part == "support"


class TestFindRecipientForAddress:
    """Tests for find_recipient_for_address wrapper."""

    @pytest.mark.asyncio
    async def test_find_recipient_wrapper(self, test_session: AsyncSession):
        """Test the wrapper function."""
        domain = Domain(domain_name="wrapper-test.com", is_enabled=True)
        test_session.add(domain)
        await test_session.flush()

        r = Recipient(
            domain_id=domain.id,
            local_part="test",
            webhook_url="https://example.com/webhook",
            is_enabled=True,
        )
        test_session.add(r)
        await test_session.commit()

        found_domain, found_recipient = await find_recipient_for_address(
            "test@wrapper-test.com", test_session
        )
        assert found_domain is not None
        assert found_recipient is not None

    @pytest.mark.asyncio
    async def test_find_recipient_not_found(self, test_session: AsyncSession):
        """Test wrapper when recipient not found."""
        found_domain, found_recipient = await find_recipient_for_address(
            "test@unknown.com", test_session
        )
        assert found_domain is None
        assert found_recipient is None


class TestEmailAuthResult:
    """Tests for EmailAuthResult dataclass."""

    def test_dkim_passed_true(self):
        """Test dkim_passed property when DKIM passes."""
        result = EmailAuthResult(
            dkim_result=RESULT_PASS,
            dkim_domain="example.com",
            dkim_selector="default",
            spf_result=RESULT_NONE,
            spf_domain=None,
            client_ip="192.168.1.1",
        )
        assert result.dkim_passed is True

    def test_dkim_passed_false(self):
        """Test dkim_passed property when DKIM fails."""
        result = EmailAuthResult(
            dkim_result=RESULT_FAIL,
            dkim_domain="example.com",
            dkim_selector="default",
            spf_result=RESULT_NONE,
            spf_domain=None,
            client_ip="192.168.1.1",
        )
        assert result.dkim_passed is False

    def test_spf_passed_true(self):
        """Test spf_passed property when SPF passes."""
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
        """Test spf_passed property when SPF fails."""
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
        """Test spf_failed property when SPF explicitly fails."""
        result = EmailAuthResult(
            dkim_result=RESULT_NONE,
            dkim_domain=None,
            dkim_selector=None,
            spf_result=RESULT_FAIL,
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        assert result.spf_failed is True

    def test_spf_failed_false_softfail(self):
        """Test spf_failed property with softfail (not hard fail)."""
        result = EmailAuthResult(
            dkim_result=RESULT_NONE,
            dkim_domain=None,
            dkim_selector=None,
            spf_result=RESULT_SOFTFAIL,
            spf_domain="example.com",
            client_ip="192.168.1.1",
        )
        assert result.spf_failed is False
