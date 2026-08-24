"""Database module."""

from fastsmtp.db.models import (
    APIKey,
    Base,
    DeliveryLog,
    Domain,
    DomainMember,
    Recipient,
    Rule,
    RuleSet,
    User,
)

# ``engine`` is deliberately not re-exported: ``db/session.py`` serves it from
# a module ``__getattr__`` that builds the engine -- and loads the full
# Settings -- on first access, so importing it here would do both at import
# time for anything that touches ``fastsmtp.db`` (the CLI entry point, the
# Alembic env). Use ``fastsmtp.db.session.get_engine()`` instead.
from fastsmtp.db.session import async_session, get_session

__all__ = [
    "APIKey",
    "Base",
    "DeliveryLog",
    "Domain",
    "DomainMember",
    "Recipient",
    "Rule",
    "RuleSet",
    "User",
    "async_session",
    "get_session",
]
