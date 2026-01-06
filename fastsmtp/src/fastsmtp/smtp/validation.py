"""Email authentication validation (DKIM and SPF)."""

import asyncio
import logging
from dataclasses import dataclass
from functools import partial

import dkim
import spf

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
    loop = asyncio.get_event_loop()
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
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None, partial(_verify_spf_sync, client_ip, mail_from, helo)
    )


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
    # Run both validations in parallel
    tasks = []

    async def dkim_none() -> tuple[str, None, None]:
        return (RESULT_NONE, None, None)

    async def spf_none() -> tuple[str, None]:
        return (RESULT_NONE, None)

    if verify_dkim_enabled:
        tasks.append(verify_dkim(message))
    else:
        tasks.append(dkim_none())

    if verify_spf_enabled:
        tasks.append(verify_spf(client_ip, mail_from, helo))
    else:
        tasks.append(spf_none())

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process DKIM result
    if isinstance(results[0], Exception):
        logger.error(f"DKIM validation exception: {results[0]}")
        dkim_result, dkim_domain, dkim_selector = RESULT_TEMPERROR, None, None
    else:
        dkim_result, dkim_domain, dkim_selector = results[0]

    # Process SPF result
    if isinstance(results[1], Exception):
        logger.error(f"SPF validation exception: {results[1]}")
        spf_result, spf_domain = RESULT_TEMPERROR, None
    else:
        spf_result, spf_domain = results[1]

    return EmailAuthResult(
        dkim_result=dkim_result,
        dkim_domain=dkim_domain,
        dkim_selector=dkim_selector,
        spf_result=spf_result,
        spf_domain=spf_domain,
        client_ip=client_ip,
    )
