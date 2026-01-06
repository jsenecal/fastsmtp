"""SMTP server module."""

from fastsmtp.smtp.server import (
    FastSMTPHandler,
    SMTPServer,
    extract_email_payload,
    find_recipient_for_address,
)
from fastsmtp.smtp.tls import (
    create_tls_context,
    get_tls_context_from_settings,
    validate_tls_config,
)
from fastsmtp.smtp.validation import (
    RESULT_FAIL,
    RESULT_NEUTRAL,
    RESULT_NONE,
    RESULT_PASS,
    RESULT_PERMERROR,
    RESULT_SOFTFAIL,
    RESULT_TEMPERROR,
    EmailAuthResult,
    validate_email_auth,
    verify_dkim,
    verify_spf,
)

__all__ = [
    "EmailAuthResult",
    "FastSMTPHandler",
    "RESULT_FAIL",
    "RESULT_NEUTRAL",
    "RESULT_NONE",
    "RESULT_PASS",
    "RESULT_PERMERROR",
    "RESULT_SOFTFAIL",
    "RESULT_TEMPERROR",
    "SMTPServer",
    "create_tls_context",
    "extract_email_payload",
    "find_recipient_for_address",
    "get_tls_context_from_settings",
    "validate_email_auth",
    "validate_tls_config",
    "verify_dkim",
    "verify_spf",
]
