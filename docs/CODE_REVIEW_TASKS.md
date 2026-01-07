# FastSMTP Code Review Tasks

This document tracks issues identified during the senior developer code review conducted on 2026-01-07.

## Priority Legend
- **P0**: Critical - Data loss or security vulnerability
- **P1**: High - Significant bugs or security concerns
- **P2**: Medium - Edge cases and performance issues
- **P3**: Low - Code quality and minor improvements

---

## P0: Critical Issues

### [ ] 1. Message Queue Data Loss Risk
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py:173-186`

**Problem:** SMTP handler queues messages to an in-memory `asyncio.Queue` and immediately returns `250 Message accepted`. If the server crashes before the message is persisted to the database, emails are lost.

**Solution:** Persist to database *before* returning 250 OK. The SMTP protocol allows delaying the response until the message is safely stored.

---

### [ ] 2. Incomplete Message Processing Pipeline
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py`

**Problem:** Messages are queued to `message_queue` but there's no visible consumer that persists them to the database via `enqueue_delivery`. The processing loop appears to be missing or disconnected.

**Solution:** Ensure the message processing pipeline is complete and transactional.

---

### [ ] 3. HTTP Client State Leak on Worker Restart
**Location:** `fastsmtp/src/fastsmtp/webhook/dispatcher.py:45-50`

**Problem:** Global `_http_client` could be used by concurrent tasks while being closed, causing race conditions.

**Solution:** Implement proper lifecycle management with reference counting or context managers.

---

## P1: Security Concerns

### [ ] 4. DNS Rebinding Attack Vector (TOCTOU)
**Location:** `fastsmtp/src/fastsmtp/webhook/url_validator.py:110-127`

**Problem:** DNS is validated at request time, but can change between validation and actual HTTP connection. Attacker could return public IP initially, then switch to `127.0.0.1`.

**Solution:** Use `httpx` event hooks to validate resolved IP at connect time, or implement a custom DNS resolver that caches results.

---

### [ ] 5. Regex Timeout Silently Bypasses Rules
**Location:** `fastsmtp/src/fastsmtp/rules/conditions.py:67-69`

**Problem:** ReDoS attacks cause silent rule bypass (returns `False` on timeout). Attacker-crafted emails could skip all regex-based spam filters.

**Solution:**
- Log timeout events as security warnings
- Consider rejecting emails if rule evaluation fails
- Add metrics for regex timeouts

---

### [ ] 6. API Key Prefix Collision / Timing Attack
**Location:** `fastsmtp/src/fastsmtp/auth/dependencies.py:166-173`

**Problem:** Key lookup by 12-char prefix could allow enumeration of valid prefixes via timing differences.

**Solution:** Add constant-time comparison at the prefix lookup stage, or use a different lookup strategy.

---

### [ ] 7. No Rate Limiting on SMTP Server
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py`

**Problem:** API has rate limiting but SMTP server accepts unlimited connections/emails.

**Solution:** Implement connection rate limiting and per-IP/per-sender throttling for the SMTP server.

---

## P2: Missing Edge Cases

### [ ] 8. Soft Delete Not Applied in SMTP Lookups
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py:45-67`

**Problem:** `lookup_recipient` doesn't filter `deleted_at IS NULL` for domains or recipients. Soft-deleted entities can still receive email.

**Solution:** Add `Domain.deleted_at.is_(None)` and `Recipient.deleted_at.is_(None)` filters.

---

### [ ] 9. Unicode/IDN Domain Handling Missing
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py:41`

**Problem:** International domain names (IDN) not normalized. `тест.com` and `xn--e1aybc.com` treated as different domains.

**Solution:** Apply punycode normalization (`idna` library) when storing and looking up domains.

---

### [ ] 10. Weak Message-ID Fallback Generation
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py:140`

**Problem:** Uses `id(envelope)` which can be reused and isn't unique across restarts.

**Solution:** Use UUID or timestamp-based generation: `f"<{uuid.uuid4()}@fastsmtp>"`.

---

### [ ] 11. Multiple NULL Catch-All Recipients Possible
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py:60-69`

**Problem:** PostgreSQL allows multiple NULLs in unique constraints. Multiple catch-all recipients could exist with undefined behavior.

**Solution:** Add a partial unique index or application-level validation to prevent multiple catch-alls per domain.

---

### [ ] 12. Multiple Recipients per Email Not Handled
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py`

**Problem:** SMTP accepts multiple `RCPT TO` but processing may not create separate webhook deliveries for each recipient.

**Solution:** Loop through `envelope.rcpt_tos` and create a delivery for each recipient.

---

### [ ] 13. Attachment Content Not Included in Webhook
**Location:** `fastsmtp/src/fastsmtp/smtp/server.py:221-225`

**Problem:** Only attachment metadata (filename, type, size) is captured, not the actual content.

**Solution:** Add option to include base64-encoded attachment content (with size limits).

---

## P2: Performance & Scalability Issues

### [ ] 14. N+1 Query in Webhook Worker
**Location:** `fastsmtp/src/fastsmtp/webhook/dispatcher.py:135-140`

**Problem:** Each delivery in a batch triggers a separate query for recipient headers.

**Solution:** Use `selectinload(DeliveryLog.recipient)` or batch recipient queries upfront.

---

### [ ] 15. Unbounded Memory in Rules Evaluation
**Location:** `fastsmtp/src/fastsmtp/rules/engine.py:161-171`

**Problem:** All rulesets and rules for a domain loaded into memory at once.

**Solution:** Consider pagination, lazy loading, or streaming evaluation for large rule sets.

---

### [ ] 16. Fixed Thread Pool Size for Regex
**Location:** `fastsmtp/src/fastsmtp/rules/conditions.py:17`

**Problem:** Fixed 4 workers regardless of load or CPU count.

**Solution:** Size based on `os.cpu_count()` or make configurable.

---

### [ ] 17. Blocking DNS Resolution in Async Context
**Location:** `fastsmtp/src/fastsmtp/webhook/url_validator.py:113`

**Problem:** `socket.getaddrinfo()` blocks the event loop.

**Solution:** Use `await loop.getaddrinfo()` for async DNS resolution.

---

### [ ] 18. Cleanup Worker May Not Keep Up
**Location:** `fastsmtp/src/fastsmtp/cleanup/`

**Problem:** With default 24-hour interval and 1000 batch size, large logs may accumulate.

**Solution:** Add backpressure mechanism or adaptive cleanup intervals.

---

## P3: Code Quality Issues

### [ ] 19. Global State in Multiple Modules
**Locations:**
- `_http_client` in `dispatcher.py`
- `_regex_executor` in `conditions.py`
- Settings via `lru_cache`

**Problem:** Makes testing harder and can cause state pollution.

**Solution:** Refactor to dependency injection pattern.

---

### [ ] 20. Inconsistent Error Handling in CLI
**Location:** `fastsmtp/src/fastsmtp/cli.py`

**Problem:** Mixed use of `typer.Exit(1)` and `typer.Abort()`.

**Solution:** Standardize on one approach for user-initiated cancellations vs errors.

---

### [ ] 21. Missing Input Validation on Rules
**Location:** `fastsmtp/src/fastsmtp/rules/conditions.py:114`

**Problem:** Invalid operators/fields silently fail instead of being caught at creation.

**Solution:** Validate operator and field values in the API when creating rules.

---

### [ ] 22. `onupdate` Doesn't Trigger on Direct SQL Updates
**Location:** `fastsmtp/src/fastsmtp/db/models.py:37`

**Problem:** SQLAlchemy's `onupdate` only works for ORM updates, not direct SQL.

**Solution:** Use database triggers or update `updated_at` explicitly in raw SQL statements.

---

## P3: Architecture Suggestions

### [ ] 23. Implement Dead Letter Queue
**Problem:** Exhausted deliveries remain in database with no alerting.

**Solution:** Add DLQ pattern with configurable alerting (webhook, email, metrics).

---

### [ ] 24. Expand Health Check Depth
**Location:** `fastsmtp/src/fastsmtp/api/operations.py`

**Problem:** `/ready` only checks database connectivity.

**Solution:** Add checks for:
- Redis connectivity (if enabled)
- Webhook worker status
- SMTP server accepting connections

---

### [ ] 25. Add Backpressure on Delivery Queue
**Problem:** Slow webhooks + fast email intake = unbounded table growth.

**Solution:** Implement admission control or circuit breakers.

---

### [ ] 26. Add Idempotency Key for Webhooks
**Problem:** Webhooks can be delivered multiple times if response is lost.

**Solution:** Include `X-Idempotency-Key` header with delivery ID.

---

### [ ] 27. Graceful Degradation When Database is Down
**Problem:** Database issues cause SMTP to reject all email.

**Solution:** Consider local disk queue as fallback.

---

## P3: Minor Issues

### [ ] 28. Duration Parsing Misleading Behavior
**Location:** `fastsmtp/src/fastsmtp/cli.py:708-709`

**Problem:** `6h` converts to 1 day minimum, which is misleading.

**Solution:** Support sub-day retention or document the minimum clearly.

---

### [ ] 29. Root User Hardcoded UUID Conflict Risk
**Location:** `fastsmtp/src/fastsmtp/auth/dependencies.py:149`

**Problem:** Hardcoded `00000000-0000-0000-0000-000000000000` could conflict.

**Solution:** Use a reserved UUID format or namespace.

---

### [ ] 30. No Maximum Webhook Payload Size
**Problem:** Large emails create large JSON payloads.

**Solution:** Add configurable payload size limit with truncation.

---

### [ ] 31. TLS Certificate Hot-Reload Not Supported
**Problem:** Certificate changes require server restart.

**Solution:** Implement periodic certificate file monitoring.

---

## Progress Summary

| Priority | Total | Completed | Remaining |
|----------|-------|-----------|-----------|
| P0       | 3     | 0         | 3         |
| P1       | 4     | 0         | 4         |
| P2       | 9     | 0         | 9         |
| P3       | 15    | 0         | 15        |
| **Total**| **31**| **0**     | **31**    |

---

## Notes

- Issues are numbered for reference but can be addressed in any order within priority
- Some issues may be deferred based on actual usage patterns
- Consider creating GitHub issues for tracking in CI/CD
