"""TLS support for SMTP server."""

import asyncio
import contextlib
import logging
import os
import ssl
from pathlib import Path

from fastsmtp.config import Settings

logger = logging.getLogger(__name__)


class TLSContextManager:
    """Manages TLS context with optional hot-reload support.

    When hot-reload is enabled, monitors certificate files for changes
    and automatically reloads the TLS context.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self._context: ssl.SSLContext | None = None
        self._cert_mtime: float = 0
        self._key_mtime: float = 0
        self._running = False
        self._task: asyncio.Task | None = None

    @property
    def context(self) -> ssl.SSLContext | None:
        """Get the current TLS context."""
        return self._context

    def _get_file_mtimes(self) -> tuple[float, float]:
        """Get modification times for cert and key files."""
        cert_path = self.settings.smtp_tls_cert
        key_path = self.settings.smtp_tls_key

        cert_mtime = 0.0
        key_mtime = 0.0

        if cert_path and cert_path.exists():
            cert_mtime = os.path.getmtime(cert_path)
        if key_path and key_path.exists():
            key_mtime = os.path.getmtime(key_path)

        return cert_mtime, key_mtime

    def _files_changed(self) -> bool:
        """Check if certificate files have changed."""
        cert_mtime, key_mtime = self._get_file_mtimes()
        return cert_mtime != self._cert_mtime or key_mtime != self._key_mtime

    def load_context(self) -> ssl.SSLContext | None:
        """Load or reload the TLS context.

        Returns:
            SSL context if successful, None otherwise
        """
        context = get_tls_context_from_settings(self.settings)
        if context:
            self._context = context
            self._cert_mtime, self._key_mtime = self._get_file_mtimes()
            logger.info("TLS context loaded successfully")
        return context

    async def _monitor_loop(self) -> None:
        """Background loop that monitors certificate files for changes."""
        interval = self.settings.smtp_tls_reload_interval
        logger.info(f"TLS hot-reload enabled, checking every {interval}s")

        while self._running:
            try:
                await asyncio.sleep(interval)
                if self._files_changed():
                    logger.info("TLS certificate files changed, reloading...")
                    new_context = get_tls_context_from_settings(self.settings)
                    if new_context:
                        self._context = new_context
                        self._cert_mtime, self._key_mtime = self._get_file_mtimes()
                        logger.info("TLS context reloaded successfully")
                    else:
                        logger.error("Failed to reload TLS context, keeping old context")
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("Error in TLS hot-reload monitor")

        logger.info("TLS hot-reload monitor stopped")

    def start_hot_reload(self) -> None:
        """Start the hot-reload monitor if enabled."""
        if not self.settings.smtp_tls_hot_reload:
            return
        if not self.settings.smtp_tls_cert or not self.settings.smtp_tls_key:
            logger.debug("TLS hot-reload not started - no TLS configured")
            return

        self._running = True
        self._task = asyncio.create_task(self._monitor_loop())

    async def stop_hot_reload(self) -> None:
        """Stop the hot-reload monitor."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task


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
