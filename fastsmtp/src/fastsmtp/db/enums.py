"""Database enum types for consistent status and role values."""

from enum import Enum


class DeliveryStatus(str, Enum):
    """Status values for webhook delivery attempts."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    EXHAUSTED = "exhausted"
    # Terminal: set when the delivery's recipient or domain is soft-deleted.
    # Never retried by the worker and never sent to the DLQ; only the retry
    # endpoint re-arms it, once both are live again.
    CANCELLED = "cancelled"


class DomainRole(str, Enum):
    """Role values for domain membership."""

    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"


class RuleAction(str, Enum):
    """Action values for rules."""

    FORWARD = "forward"
    DROP = "drop"
    TAG = "tag"
    QUARANTINE = "quarantine"


class RuleOperator(str, Enum):
    """Operator values for rule conditions."""

    EQUALS = "equals"
    CONTAINS = "contains"
    REGEX = "regex"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    EXISTS = "exists"


class RuleField(str, Enum):
    """Field values for rule conditions."""

    FROM = "from"
    TO = "to"
    SUBJECT = "subject"
    BODY = "body"
    HAS_ATTACHMENT = "has_attachment"
    DKIM_RESULT = "dkim_result"
    SPF_RESULT = "spf_result"
    # Custom headers use "header:X-Custom-Header" format, validated separately
