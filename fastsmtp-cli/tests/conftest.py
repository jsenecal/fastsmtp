"""Shared test configuration for the CLI package.

``test_api_contract`` imports ``fastsmtp.main`` to build the server's OpenAPI
document, and that module resolves settings at import time. Without these
variables the import raises before any fixture argument can supply them, so the
contract tests error out whenever this package's tests run on their own rather
than as part of the full suite.
"""

import os

# Set required environment variables before any imports
os.environ.setdefault("FASTSMTP_ROOT_API_KEY", "test_root_api_key_12345")
os.environ.setdefault("FASTSMTP_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
