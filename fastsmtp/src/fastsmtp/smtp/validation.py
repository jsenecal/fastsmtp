"""Email authentication validation (DKIM and SPF)."""

import asyncio
import binascii
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from email.parser import BytesHeaderParser
from email.policy import compat32
from email.utils import getaddresses
from functools import partial
from typing import TYPE_CHECKING, TypeVar

import dkim
import dkim.dnsplug
import dkim.util
import spf

if TYPE_CHECKING:
    from fastsmtp.config import Settings
    from fastsmtp.db.models import Domain

logger = logging.getLogger(__name__)

# Result constants
RESULT_PASS = "pass"
RESULT_FAIL = "fail"
RESULT_SOFTFAIL = "softfail"
RESULT_NEUTRAL = "neutral"
RESULT_NONE = "none"
RESULT_TEMPERROR = "temperror"
RESULT_PERMERROR = "permerror"

# Mechanism names, as they are reported to an operator and to a sender: they
# are part of the "550 <mechanism> verification failed" reply, so they are
# spelled once here rather than in every module that names one.
MECHANISM_DKIM = "DKIM"
MECHANISM_SPF = "SPF"


@dataclass(frozen=True)
class EmailAuthResult:
    """Results of email authentication validation.

    Frozen because one result is computed for the whole message and then
    shared: :meth:`EffectiveAuthPolicy.masked` hands the same instance to
    every recipient whose domain verifies both mechanisms, so a mutation
    would follow the message to recipients that never asked for it.
    """

    dkim_result: str  # pass, fail, none, temperror, permerror
    dkim_domain: str | None
    dkim_selector: str | None
    spf_result: str  # pass, fail, softfail, neutral, none, temperror, permerror
    spf_domain: str | None
    client_ip: str

    @property
    def dkim_passed(self) -> bool:
        """Check if DKIM verification passed."""
        return self.dkim_result == RESULT_PASS

    @property
    def spf_passed(self) -> bool:
        """Check if SPF verification passed."""
        return self.spf_result == RESULT_PASS

    @property
    def spf_failed(self) -> bool:
        """Check if SPF verification explicitly failed (not softfail/neutral/none)."""
        return self.spf_result == RESULT_FAIL


@dataclass(frozen=True)
class EffectiveAuthPolicy:
    """The DKIM and SPF policy in force for one recipient domain.

    Every flag is already resolved: the domain's own override where it has
    one, the server-wide setting where the column is NULL.
    """

    verify_dkim: bool
    verify_spf: bool
    reject_dkim_fail: bool
    reject_spf_fail: bool

    def masked(self, auth_result: EmailAuthResult) -> EmailAuthResult:
        """``auth_result`` as this domain is entitled to see it.

        A mechanism is verified once for the whole message if *any* recipient
        domain asks for it, so a domain that set ``verify_dkim`` to false can
        be handed a DKIM decision it never asked for. Everything such a
        mechanism produced is blanked back to "not checked" here, so the
        domain's rules match ``dkim_result`` as ``none`` and its webhook
        payload and delivery log record the same.

        Returns ``auth_result`` itself when the domain verifies both
        mechanisms; nothing mutates it.
        """
        if self.verify_dkim and self.verify_spf:
            return auth_result
        return replace(
            auth_result,
            dkim_result=auth_result.dkim_result if self.verify_dkim else RESULT_NONE,
            dkim_domain=auth_result.dkim_domain if self.verify_dkim else None,
            dkim_selector=auth_result.dkim_selector if self.verify_dkim else None,
            spf_result=auth_result.spf_result if self.verify_spf else RESULT_NONE,
            spf_domain=auth_result.spf_domain if self.verify_spf else None,
        )

    def refused_mechanism(self, auth_result: EmailAuthResult) -> str | None:
        """Name the mechanism this policy refuses the message on, if any.

        The decision is made on what this domain is shown (:meth:`masked`),
        which is why a domain that does not verify a mechanism cannot reject
        on it: the result it would be judging was never computed for it, and
        ``fail`` there would mean "another recipient's domain asked for this
        check", not anything this domain decided.

        DKIM is reported ahead of SPF when both refuse, so a message that
        fails everything is refused with the reply it always was.
        """
        visible = self.masked(auth_result)
        if self.reject_dkim_fail and visible.dkim_result == RESULT_FAIL:
            return MECHANISM_DKIM
        if self.reject_spf_fail and visible.spf_result == RESULT_FAIL:
            return MECHANISM_SPF
        return None


def resolve_auth_policy(domain: "Domain | None", settings: "Settings") -> EffectiveAuthPolicy:
    """Resolve a recipient domain's auth policy against the global settings.

    The four ``Domain`` columns are tri-state: NULL inherits the matching
    ``FASTSMTP_SMTP_*`` setting, true and false override it. ``domain`` is
    None for an address that resolves to no configured domain -- never
    configured, or tombstoned between RCPT and DATA -- which keeps the global
    policy, exactly as before domains could override anything.

    Takes the loaded row rather than an id so the receive path, which already
    holds it, does not pay for a second query.
    """

    def resolve(override: bool | None, default: bool) -> bool:
        return default if override is None else bool(override)

    return EffectiveAuthPolicy(
        verify_dkim=resolve(domain.verify_dkim if domain else None, settings.smtp_verify_dkim),
        verify_spf=resolve(domain.verify_spf if domain else None, settings.smtp_verify_spf),
        reject_dkim_fail=resolve(
            domain.reject_dkim_fail if domain else None, settings.smtp_reject_dkim_fail
        ),
        reject_spf_fail=resolve(
            domain.reject_spf_fail if domain else None, settings.smtp_reject_spf_fail
        ),
    )


# A message can carry any number of DKIM-Signature headers and every one costs a
# key lookup, so only a few are checked, and all their lookups share one time
# budget: a sender cannot hold a worker thread for MAX x the per-lookup timeout
# by stacking signatures whose d= points at a dead nameserver. Mail
# legitimately carries one to three (author, ESP, mailing list).
MAX_DKIM_SIGNATURES = 5
DKIM_LOOKUP_BUDGET_SECONDS = 10.0

# Which result to report when no signature passes. A temperror outranks a fail
# because the signature that timed out may pass on retry, and reporting fail
# would let ``reject_dkim_fail`` refuse a message that could be genuine. A fail
# outranks a permerror: a broken signature says nothing about the message,
# while a fail is a positive verdict from the signer's own key.
_DKIM_RANK = {RESULT_TEMPERROR: 0, RESULT_FAIL: 1, RESULT_PERMERROR: 2}

TxtLookup = Callable[..., bytes | None]


def _signer(d: "dkim.DKIM") -> tuple[str | None, str | None]:
    """The ``d=`` and ``s=`` of the signature ``d`` last parsed.

    Read from ``signature_fields``, which dkimpy fills in before validating the
    signature, rather than ``d.domain``/``d.selector``, which it sets only once
    validation passes and which default to ``None`` and ``'default'``.
    """

    def tag(name: bytes) -> str | None:
        value = d.signature_fields.get(name)
        return value.decode("ascii", errors="replace") if value else None

    return tag(b"d"), tag(b"s")


def _from_domain(message: bytes) -> str | None:
    """The ``From:`` address's domain, lowercased, for ordering signatures."""
    addresses = getaddresses(
        BytesHeaderParser(policy=compat32).parsebytes(message).get_all("From", [])
    )
    for _, address in addresses:
        if "@" in address:
            return address.rsplit("@", 1)[1].lower()
    return None


def _aligned(signing_domain: str | None, from_domain: str | None) -> bool:
    """``From:`` is the signing domain or below it.

    A heuristic for which signature to check and report first, nothing more:
    without a public suffix list it cannot tell ``d=co.uk`` from a real
    organizational domain, so nothing may trust it as DMARC alignment.
    """
    if not signing_domain or not from_domain:
        return False
    signing_domain = signing_domain.lower()
    return from_domain == signing_domain or from_domain.endswith("." + signing_domain)


def _signature_order(sig_values: list[bytes], from_domain: str | None) -> list[int]:
    """Indices of the signatures to check, ``From``-aligned ones first.

    Anyone relaying the message can prepend signatures, so checking strictly
    top-down would let a handful of junk ones push the author's own past
    ``MAX_DKIM_SIGNATURES``. Otherwise topmost first, as RFC 6376 suggests.
    """

    def signing_domain(value: bytes) -> str | None:
        try:
            d = dkim.util.parse_tag_value(value).get(b"d")
        except Exception:
            return None
        return d.decode("ascii", errors="replace") if d else None

    aligned = [i for i, v in enumerate(sig_values) if _aligned(signing_domain(v), from_domain)]
    rest = [i for i in range(len(sig_values)) if i not in aligned]
    return (aligned + rest)[:MAX_DKIM_SIGNATURES]


def _verify_one_signature(
    message: bytes, idx: int, dnsfunc: TxtLookup, deadline: float
) -> tuple[str, str | None, str | None]:
    """Verify the ``idx``-th DKIM-Signature (0 is topmost).

    dkimpy's ``verify()`` swallows key-lookup failures and returns False, so a
    missing key, an unparseable key and a DNS timeout all look like a bad
    signature. The lookup is wrapped to see which of those it was, and to hold
    it to what is left of ``deadline``. The domain and selector are read back
    from the same ``DKIM`` object that verified, the only one dkimpy fills in.
    """
    lookup: dict[str, object] = {}

    def recording_dnsfunc(name: bytes, timeout: float = 5) -> bytes | None:
        remaining = deadline - time.monotonic()
        try:
            if remaining <= 0:
                raise dkim.DnsTimeoutError("DKIM lookup budget exhausted")
            record = dnsfunc(name, timeout=min(timeout, remaining))
        except dkim.DnsTimeoutError:
            lookup["outcome"] = RESULT_TEMPERROR
            raise
        lookup["outcome"] = "answered" if record else RESULT_PERMERROR
        lookup["record"] = record
        return record

    d = dkim.DKIM(message)
    try:
        ok = d.verify(idx=idx, dnsfunc=recording_dnsfunc)
    except dkim.ValidationError as e:
        # Raised before the key is fetched for a malformed signature, and after
        # it for a body hash mismatch or a key unusable for this message (its
        # s= service type). Only the body hash is a verdict on the message.
        body_mismatch = "outcome" in lookup and str(e).startswith("body hash mismatch")
        return (RESULT_FAIL if body_mismatch else RESULT_PERMERROR, *_signer(d))
    except dkim.DKIMException as e:
        logger.info(f"DKIM signature {idx} unverifiable: {e}")
        return (RESULT_PERMERROR, *_signer(d))

    domain, selector = _signer(d)
    if ok:
        return RESULT_PASS, domain, selector
    outcome = lookup.get("outcome")
    if outcome in (RESULT_TEMPERROR, RESULT_PERMERROR):
        return str(outcome), domain, selector
    if outcome == "answered":
        try:
            dkim.evaluate_pk(b"", lookup["record"])
        except (dkim.KeyFormatError, binascii.Error):
            return RESULT_PERMERROR, domain, selector
    return RESULT_FAIL, domain, selector


def _verify_dkim_sync(
    message: bytes, dnsfunc: TxtLookup | None = None
) -> tuple[str, str | None, str | None]:
    """Verify the message's DKIM signatures (up to a cap) and summarise.

    Any passing signature makes the message pass, preferring one whose ``d=``
    is the ``From:`` domain or a parent of it. Otherwise the most hopeful
    failure is reported, see ``_DKIM_RANK``. Unsigned mail is ``none``.

    Args:
        message: Raw email message bytes
        dnsfunc: TXT lookup, for tests. Defaults to dkimpy's resolver, looked up
            at call time so it can be patched.

    Returns:
        Tuple of (result, domain, selector)
    """
    if dnsfunc is None:
        dnsfunc = dkim.dnsplug.get_txt
    try:
        sig_values = [
            value for name, value in dkim.DKIM(message).headers if name.lower() == b"dkim-signature"
        ]
    except dkim.DKIMException as e:
        logger.warning(f"DKIM: unparseable message: {e}")
        return RESULT_PERMERROR, None, None
    except Exception as e:
        logger.error(f"Unexpected DKIM error: {e}")
        return RESULT_TEMPERROR, None, None
    if not sig_values:
        return RESULT_NONE, None, None

    from_domain = _from_domain(message)
    deadline = time.monotonic() + DKIM_LOOKUP_BUDGET_SECONDS
    results = []
    for idx in _signature_order(sig_values, from_domain):
        try:
            result = _verify_one_signature(message, idx, dnsfunc, deadline)
        except Exception as e:
            logger.error(f"Unexpected DKIM error on signature {idx}: {e}")
            result = (RESULT_TEMPERROR, None, None)
        if result[0] == RESULT_PASS and _aligned(result[1], from_domain):
            return result
        results.append(result)

    passes = [r for r in results if r[0] == RESULT_PASS]
    if passes:
        return passes[0]
    # min() keeps the first of equal rank, so ties go to the first one checked.
    return min(results, key=lambda r: _DKIM_RANK[r[0]])


async def verify_dkim(message: bytes) -> tuple[str, str | None, str | None]:
    """Verify DKIM signature asynchronously.

    Runs the CPU-bound DKIM verification in a thread pool executor.

    Args:
        message: Raw email message bytes

    Returns:
        Tuple of (result, domain, selector)
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(_verify_dkim_sync, message))


def _verify_spf_sync(client_ip: str, mail_from: str, helo: str) -> tuple[str, str | None]:
    """Synchronously verify SPF record.

    Args:
        client_ip: IP address of the sending server
        mail_from: MAIL FROM address
        helo: HELO/EHLO hostname

    Returns:
        Tuple of (result, domain)
    """
    try:
        # Extract domain from mail_from
        domain = mail_from.split("@")[1] if mail_from and "@" in mail_from else helo

        # spf.check2 returns (result_code, result_string)
        # result_code: pass, fail, softfail, neutral, none, temperror, permerror
        result_code, _ = spf.check2(i=client_ip, s=mail_from, h=helo)

        # Normalize result
        result_map = {
            "pass": RESULT_PASS,
            "fail": RESULT_FAIL,
            "softfail": RESULT_SOFTFAIL,
            "neutral": RESULT_NEUTRAL,
            "none": RESULT_NONE,
            "temperror": RESULT_TEMPERROR,
            "permerror": RESULT_PERMERROR,
        }
        result = result_map.get(result_code, RESULT_NONE)

        return result, domain
    except Exception as e:
        logger.error(f"SPF verification error: {e}")
        return RESULT_TEMPERROR, None


async def verify_spf(client_ip: str, mail_from: str, helo: str) -> tuple[str, str | None]:
    """Verify SPF record asynchronously.

    Runs the SPF verification in a thread pool executor since it does DNS lookups.

    Args:
        client_ip: IP address of the sending server
        mail_from: MAIL FROM address
        helo: HELO/EHLO hostname

    Returns:
        Tuple of (result, domain)
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(_verify_spf_sync, client_ip, mail_from, helo))


_T = TypeVar("_T")


def _result_or_temperror(raw: _T | BaseException, label: str, temperror: _T) -> _T:
    """Unwrap one ``asyncio.gather(..., return_exceptions=True)`` slot.

    gather hands back the *instance* for a failed child rather than raising, and
    for a cancelled child that instance is a ``CancelledError`` -- a
    ``BaseException``, not an ``Exception``. Cancellation is re-raised so it
    keeps propagating, matching the ``except Exception`` of the single-validator
    paths below; ordinary failures degrade to a temperror.
    """
    if isinstance(raw, BaseException):
        if not isinstance(raw, Exception):
            raise raw
        logger.error(f"{label} validation exception: {raw}")
        return temperror
    return raw


async def validate_email_auth(
    message: bytes,
    client_ip: str,
    mail_from: str,
    helo: str,
    verify_dkim_enabled: bool = True,
    verify_spf_enabled: bool = True,
) -> EmailAuthResult:
    """Run DKIM and SPF validation in parallel.

    Args:
        message: Raw email message bytes
        client_ip: IP address of the sending server
        mail_from: MAIL FROM address
        helo: HELO/EHLO hostname
        verify_dkim_enabled: Whether to verify DKIM
        verify_spf_enabled: Whether to verify SPF

    Returns:
        EmailAuthResult with validation results
    """
    # Set up coroutines based on what's enabled
    dkim_coro = verify_dkim(message) if verify_dkim_enabled else None
    spf_coro = verify_spf(client_ip, mail_from, helo) if verify_spf_enabled else None

    # Run validations in parallel if both enabled
    dkim_result: str = RESULT_NONE
    dkim_domain: str | None = None
    dkim_selector: str | None = None
    spf_result: str = RESULT_NONE
    spf_domain: str | None = None

    if dkim_coro and spf_coro:
        # Run both in parallel using gather (safer than create_task in mixed event loop contexts)
        dkim_raw, spf_raw = await asyncio.gather(dkim_coro, spf_coro, return_exceptions=True)

        dkim_result, dkim_domain, dkim_selector = _result_or_temperror(
            dkim_raw, "DKIM", (RESULT_TEMPERROR, None, None)
        )
        spf_result, spf_domain = _result_or_temperror(spf_raw, "SPF", (RESULT_TEMPERROR, None))
    elif dkim_coro:
        try:
            dkim_result, dkim_domain, dkim_selector = await dkim_coro
        except Exception as e:
            logger.error(f"DKIM validation exception: {e}")
            dkim_result, dkim_domain, dkim_selector = RESULT_TEMPERROR, None, None
    elif spf_coro:
        try:
            spf_result, spf_domain = await spf_coro
        except Exception as e:
            logger.error(f"SPF validation exception: {e}")
            spf_result, spf_domain = RESULT_TEMPERROR, None

    return EmailAuthResult(
        dkim_result=dkim_result,
        dkim_domain=dkim_domain,
        dkim_selector=dkim_selector,
        spf_result=spf_result,
        spf_domain=spf_domain,
        client_ip=client_ip,
    )
