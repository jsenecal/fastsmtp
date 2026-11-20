"""DKIM verification against real signatures (issue #184).

Every test signs a message with a throwaway RSA key and answers the key lookup
from a dict, so nothing here touches the network. The DNS function is passed
straight in for the unit tests and patched onto ``dkim.dnsplug`` for the one
that goes through the SMTP handler, which has no way to pass one.
"""

import base64
from collections.abc import Callable
from unittest.mock import MagicMock, patch

import dkim
import dkim.dnsplug
import pytest
from aiosmtpd.smtp import Envelope
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastsmtp.config import Settings
from fastsmtp.smtp import validation
from fastsmtp.smtp.server import FastSMTPHandler
from fastsmtp.smtp.validation import (
    MAX_DKIM_SIGNATURES,
    RESULT_FAIL,
    RESULT_NONE,
    RESULT_PASS,
    RESULT_PERMERROR,
    RESULT_TEMPERROR,
    _verify_dkim_sync,
)

MESSAGE = (
    b"From: sender@example.com\r\n"
    b"To: recipient@test.com\r\n"
    b"Subject: Test\r\n"
    b"Date: Fri, 20 Nov 2026 10:00:00 +0000\r\n"
    b"Message-ID: <184@example.com>\r\n"
    b"\r\n"
    b"Test body.\r\n"
)


class Signer:
    """One RSA key, able to sign as any domain/selector and publish its record."""

    def __init__(self) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        public_der = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public_der)

    def sign(self, message: bytes, domain: str, selector: str) -> bytes:
        header = dkim.sign(message, selector.encode(), domain.encode(), self.private_pem)
        return bytes(header) + message


@pytest.fixture(scope="module")
def signer() -> Signer:
    return Signer()


@pytest.fixture(scope="module")
def other_signer() -> Signer:
    return Signer()


def dns(records: dict[str, bytes]) -> Callable[..., bytes | None]:
    """A dkimpy ``dnsfunc`` answering from ``records``; anything else is NXDOMAIN."""

    def lookup(name: bytes, timeout: int = 5) -> bytes | None:
        return records.get(name.decode().rstrip("."))

    return lookup


def timing_out(name: bytes, timeout: int = 5) -> bytes | None:
    raise dkim.DnsTimeoutError("dns.exception.Timeout: simulated")


def tamper(message: bytes) -> bytes:
    return message.replace(b"Test body.", b"Test bodY.")


class TestSingleSignature:
    def test_pass_reports_domain_and_selector(self, signer: Signer):
        message = signer.sign(MESSAGE, "example.com", "s1")

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": signer.record})
        )

        assert result == (RESULT_PASS, "example.com", "s1")

    def test_tampered_body_is_fail_with_domain(self, signer: Signer):
        message = tamper(signer.sign(MESSAGE, "example.com", "s1"))

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": signer.record})
        )

        assert result == (RESULT_FAIL, "example.com", "s1")

    def test_tampered_signed_header_is_fail_with_domain(self, signer: Signer):
        message = signer.sign(MESSAGE, "example.com", "s1").replace(
            b"Subject: Test", b"Subject: Tset"
        )

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": signer.record})
        )

        assert result == (RESULT_FAIL, "example.com", "s1")

    def test_wrong_key_is_fail(self, signer: Signer, other_signer: Signer):
        message = signer.sign(MESSAGE, "example.com", "s1")

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": other_signer.record})
        )

        assert result == (RESULT_FAIL, "example.com", "s1")

    def test_missing_key_record_is_permerror(self, signer: Signer):
        message = signer.sign(MESSAGE, "example.com", "s1")

        result = _verify_dkim_sync(message, dnsfunc=dns({}))

        assert result == (RESULT_PERMERROR, "example.com", "s1")

    def test_malformed_key_record_is_permerror(self, signer: Signer):
        message = signer.sign(MESSAGE, "example.com", "s1")

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": b"v=DKIM1; k=rsa; p=!!!"})
        )

        assert result == (RESULT_PERMERROR, "example.com", "s1")

    def test_dns_timeout_is_temperror(self, signer: Signer):
        message = signer.sign(MESSAGE, "example.com", "s1")

        result = _verify_dkim_sync(message, dnsfunc=timing_out)

        assert result == (RESULT_TEMPERROR, "example.com", "s1")

    def test_unparseable_signature_is_permerror(self):
        message = b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com\r\n" + MESSAGE

        result = _verify_dkim_sync(message, dnsfunc=dns({}))

        # Missing s=, so there is no selector to report; d= is still named.
        assert result == (RESULT_PERMERROR, "example.com", None)

    def test_unsigned_is_none(self):
        assert _verify_dkim_sync(MESSAGE, dnsfunc=dns({})) == (RESULT_NONE, None, None)


class TestSeveralSignatures:
    def test_second_signature_passing_is_pass(self, signer: Signer):
        # The topmost signature (added last) is for a domain whose key is gone.
        message = signer.sign(signer.sign(MESSAGE, "example.com", "s1"), "relay.test", "r1")

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": signer.record})
        )

        assert result == (RESULT_PASS, "example.com", "s1")

    def test_pass_aligned_with_from_is_preferred(self, signer: Signer):
        message = signer.sign(signer.sign(MESSAGE, "example.com", "s1"), "esp.test", "e1")

        result = _verify_dkim_sync(
            message,
            dnsfunc=dns(
                {
                    "s1._domainkey.example.com": signer.record,
                    "e1._domainkey.esp.test": signer.record,
                }
            ),
        )

        assert result == (RESULT_PASS, "example.com", "s1")

    def test_temperror_outranks_fail(self, signer: Signer):
        """A signature that may still pass on retry must not let another reject it."""
        message = tamper(signer.sign(MESSAGE, "example.com", "s1"))
        message = signer.sign(message, "slow.test", "t1")
        records = {"s1._domainkey.example.com": signer.record}

        def lookup(name: bytes, timeout: int = 5) -> bytes | None:
            if name.startswith(b"t1._domainkey.slow.test"):
                raise dkim.DnsTimeoutError("simulated")
            return dns(records)(name, timeout)

        result = _verify_dkim_sync(message, dnsfunc=lookup)

        assert result == (RESULT_TEMPERROR, "slow.test", "t1")

    def test_fail_outranks_permerror(self, signer: Signer):
        message = tamper(signer.sign(MESSAGE, "example.com", "s1"))
        message = signer.sign(message, "gone.test", "g1")

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": signer.record})
        )

        assert result == (RESULT_FAIL, "example.com", "s1")

    def test_junk_prepended_signatures_do_not_hide_the_authors(self, signer: Signer):
        """A relay can prepend signatures; the From-aligned one is still checked."""
        message = signer.sign(MESSAGE, "example.com", "s1")
        for n in range(MAX_DKIM_SIGNATURES + 2):
            message = signer.sign(message, f"junk{n}.test", "j")

        result = _verify_dkim_sync(
            message, dnsfunc=dns({"s1._domainkey.example.com": signer.record})
        )

        assert result == (RESULT_PASS, "example.com", "s1")

    def test_lookups_share_one_time_budget(self, signer: Signer, monkeypatch):
        """Stacked slow lookups cannot hold the worker past the budget."""
        message = signer.sign(MESSAGE, "example.com", "s1")
        for n in range(3):
            message = signer.sign(message, f"slow{n}.test", "t")
        monkeypatch.setattr(validation, "DKIM_LOOKUP_BUDGET_SECONDS", 1.0)
        clock = [0.0]
        monkeypatch.setattr(validation.time, "monotonic", lambda: clock[0])
        timeouts: list[float] = []

        def slow(name: bytes, timeout: float = 5) -> bytes | None:
            timeouts.append(timeout)
            clock[0] += timeout  # every lookup burns all it is given
            raise dkim.DnsTimeoutError("simulated")

        result = _verify_dkim_sync(message, dnsfunc=slow)

        assert result[0] == RESULT_TEMPERROR
        assert timeouts == [1.0]  # the first used it up; the rest never asked DNS


class TestKeyServiceType:
    def test_key_restricted_to_tlsrpt_is_permerror_not_fail(self, signer: Signer):
        """An unusable key is not a verdict on the message, so not refusable."""
        message = signer.sign(MESSAGE, "example.com", "s1")

        result = _verify_dkim_sync(
            message,
            dnsfunc=dns({"s1._domainkey.example.com": signer.record + b"; s=tlsrpt"}),
        )

        assert result == (RESULT_PERMERROR, "example.com", "s1")


class TestHandlerRejectsRealFailure:
    @pytest.mark.asyncio
    async def test_reject_dkim_fail_rejects_a_tampered_message(
        self, signer: Signer, make_smtp_settings: Callable[..., Settings], session_factory
    ):
        """End to end through the real validator: before #184 this read as none."""
        settings = make_smtp_settings(
            smtp_verify_dkim=True,
            smtp_verify_spf=False,
            smtp_reject_dkim_fail=True,
        )
        handler = FastSMTPHandler(settings)

        session = MagicMock()
        session.peer = ("127.0.0.1", 12345)
        session.host_name = "test-client"
        envelope = Envelope()
        envelope.mail_from = "sender@example.com"
        envelope.rcpt_tos = ["recipient@test.com"]
        envelope.content = tamper(signer.sign(MESSAGE, "example.com", "s1"))

        with (
            patch("fastsmtp.smtp.server.async_session", session_factory),
            patch.object(
                dkim.dnsplug,
                "get_txt",
                dns({"s1._domainkey.example.com": signer.record}),
            ),
        ):
            reply = await handler.handle_DATA(MagicMock(), session, envelope)

        assert reply.startswith("550")
        assert "DKIM" in reply
