"""TLS support for SMTP server."""

import logging
import ssl
from pathlib import Path

from fastsmtp.config import Settings

logger = logging.getLogger(__name__)


def create_tls_context(
    cert_path: Path,
    key_path: Path,
    require_client_cert: bool = False,
) -> ssl.SSLContext:
    """Create an SSL context for SMTP TLS.

    Args:
        cert_path: Path to the TLS certificate file
        key_path: Path to the TLS private key file
        require_client_cert: Whether to require client certificates

    Returns:
        Configured SSL context
    """
    # Create context with secure defaults
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Load certificate and key
    context.load_cert_chain(
        certfile=str(cert_path),
        keyfile=str(key_path),
    )

    # Set secure options
    context.options |= ssl.OP_NO_SSLv2
    context.options |= ssl.OP_NO_SSLv3
    context.options |= ssl.OP_NO_TLSv1
    context.options |= ssl.OP_NO_TLSv1_1

    # Set cipher suites (prefer modern ciphers)
    context.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+CHACHA20:DHE+CHACHA20:!aNULL:!MD5:!DSS")

    # Client certificate verification
    if require_client_cert:
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.verify_mode = ssl.CERT_NONE

    return context


def get_tls_context_from_settings(settings: Settings) -> ssl.SSLContext | None:
    """Create TLS context from application settings.

    Args:
        settings: Application settings

    Returns:
        SSL context if TLS is configured, None otherwise
    """
    if not settings.smtp_tls_cert or not settings.smtp_tls_key:
        logger.debug("TLS not configured - no certificate or key provided")
        return None

    cert_path = settings.smtp_tls_cert
    key_path = settings.smtp_tls_key

    if not cert_path.exists():
        logger.error(f"TLS certificate not found: {cert_path}")
        return None

    if not key_path.exists():
        logger.error(f"TLS key not found: {key_path}")
        return None

    try:
        context = create_tls_context(cert_path, key_path)
        logger.info("TLS context created successfully")
        return context
    except Exception as e:
        logger.error(f"Failed to create TLS context: {e}")
        return None


def validate_tls_config(settings: Settings) -> tuple[bool, str]:
    """Validate TLS configuration.

    Args:
        settings: Application settings

    Returns:
        Tuple of (is_valid, message)
    """
    if not settings.smtp_tls_cert and not settings.smtp_tls_key:
        return True, "TLS not configured"

    if settings.smtp_tls_cert and not settings.smtp_tls_key:
        return False, "TLS certificate provided but no key"

    if settings.smtp_tls_key and not settings.smtp_tls_cert:
        return False, "TLS key provided but no certificate"

    cert_path = settings.smtp_tls_cert
    key_path = settings.smtp_tls_key

    # After the above checks, both must be set if we reach here
    if cert_path is None or key_path is None:
        return True, "TLS not configured"

    if not cert_path.exists():
        return False, f"TLS certificate not found: {cert_path}"

    if not key_path.exists():
        return False, f"TLS key not found: {key_path}"

    # Try to create context to validate cert/key pair
    try:
        create_tls_context(cert_path, key_path)
        return True, "TLS configuration valid"
    except ssl.SSLError as e:
        return False, f"TLS configuration error: {e}"
    except Exception as e:
        return False, f"Unexpected error validating TLS: {e}"
