"""Email authentication validation (DKIM and SPF)."""

import asyncio
import logging
from dataclasses import dataclass
from functools import partial
from typing import TYPE_CHECKING, TypeVar

import dkim
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


@dataclass
class EmailAuthResult:
    """Results of email authentication validation."""

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

    def refused_mechanism(self, auth_result: EmailAuthResult) -> str | None:
        """Name the mechanism this policy refuses the message on, if any.

        A domain that does not verify a mechanism cannot reject on it: the
        result it would be judging was never computed, and ``fail`` there
        would mean "another recipient's domain asked for this check", not
        anything this domain decided.

        DKIM is reported ahead of SPF when both refuse, so a message that
        fails everything is refused with the reply it always was.
        """
        if self.verify_dkim and self.reject_dkim_fail and auth_result.dkim_result == RESULT_FAIL:
            return "DKIM"
        if self.verify_spf and self.reject_spf_fail and auth_result.spf_result == RESULT_FAIL:
            return "SPF"
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


def _verify_dkim_sync(message: bytes) -> tuple[str, str | None, str | None]:
    """Synchronously verify DKIM signature.

    Args:
        message: Raw email message bytes

    Returns:
        Tuple of (result, domain, selector)
    """
    try:
        # dkim.verify returns True/False
        result = dkim.verify(message)
        if result:
            # Try to extract domain and selector from signature
            try:
                sig = dkim.DKIM(message)
                domain = sig.domain.decode() if sig.domain else None
                selector = sig.selector.decode() if sig.selector else None
                return RESULT_PASS, domain, selector
            except Exception:
                return RESULT_PASS, None, None
        else:
            # Check if there was a signature at all
            try:
                sig = dkim.DKIM(message)
                if sig.signature_fields:
                    domain = sig.domain.decode() if sig.domain else None
                    selector = sig.selector.decode() if sig.selector else None
                    return RESULT_FAIL, domain, selector
                else:
                    return RESULT_NONE, None, None
            except Exception:
                return RESULT_FAIL, None, None
    except dkim.DKIMException as e:
        logger.warning(f"DKIM verification error: {e}")
        if "DNS" in str(e) or "timeout" in str(e).lower():
            return RESULT_TEMPERROR, None, None
        return RESULT_PERMERROR, None, None
    except Exception as e:
        logger.error(f"Unexpected DKIM error: {e}")
        return RESULT_TEMPERROR, None, None


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
