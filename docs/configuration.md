# Configuration

All configuration is via environment variables with the `FASTSMTP_` prefix.

A `.env` file in the working directory is read as well, and an exported variable
wins over the same key in the file. It is resolved relative to the directory the
command is started from, and every command resolves it the same way: `fastsmtp
serve`, `fastsmtp show-config` and `fastsmtp db upgrade head` run from one shell
all reach the same database.

## SMTP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_SMTP_HOST` | `0.0.0.0` | SMTP bind address |
| `FASTSMTP_SMTP_PORT` | `2525` | Plain SMTP port |
| `FASTSMTP_SMTP_TLS_PORT` | `4650` | TLS SMTP port |
| `FASTSMTP_SMTP_TLS_CERT` | - | Path to TLS certificate |
| `FASTSMTP_SMTP_TLS_KEY` | - | Path to TLS private key |
| `FASTSMTP_SMTP_REQUIRE_STARTTLS` | `false` | Enforce STARTTLS |
| `FASTSMTP_SMTP_MAX_MESSAGE_SIZE` | `10485760` | Largest message accepted, in bytes (10 MB) |
| `FASTSMTP_SMTP_TLS_HOT_RELOAD` | `false` | Watch the certificate and key files and reload them without a restart |
| `FASTSMTP_SMTP_TLS_RELOAD_INTERVAL` | `300` | Seconds between hot-reload checks |

Hot reload only starts when both `FASTSMTP_SMTP_TLS_CERT` and `FASTSMTP_SMTP_TLS_KEY`
are set; without it a renewed certificate is picked up on the next restart.

## Email Validation

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_SMTP_VERIFY_DKIM` | `true` | Enable DKIM verification |
| `FASTSMTP_SMTP_VERIFY_SPF` | `true` | Enable SPF verification |
| `FASTSMTP_SMTP_REJECT_DKIM_FAIL` | `false` | Reject emails on DKIM failure |
| `FASTSMTP_SMTP_REJECT_SPF_FAIL` | `false` | Reject emails on SPF failure |

### Per-domain overrides

These four are defaults, not the final word. Every domain has a matching
`verify_dkim`, `verify_spf`, `reject_dkim_fail` and `reject_spf_fail` field, unset
by default (`inherit`) so the domain follows the setting above; set to `true` or
`false` it overrides that setting for mail addressed to the domain, at receive
time. They are **superuser only**: `POST /domains` and `PUT /domains/{id}` answer
`403` to anyone else, since a domain admin could otherwise opt out of the
server-wide reject policy. Set them with `fsmtp domain create/update` or
`PUT /domains/{id}`; send `null` (`inherit`) to go back to following the server.

Three rules make this predictable when a message has recipients on more than one
domain:

- A check runs once for the message if **any** recipient's domain verifies that
  mechanism. The result is shown only to the domains that asked for it: for a
  domain with `verify_dkim` set to `false`, `dkim_result` is `none` in its rules,
  its webhook payload and its delivery log, whatever the check found.
- A domain can only reject on a mechanism it also verifies, so
  `reject_dkim_fail: true` with `verify_dkim: false` rejects nothing.
- **The strictest recipient policy wins.** If any one recipient's domain refuses
  the message, the whole message is refused with `550 DKIM verification failed`
  or `550 SPF verification failed` (DKIM is named when the refusals mix
  mechanisms) and nobody is delivered to. Accepting for the other recipients
  would mean answering `250` and then discarding the message for the refusing
  one, which is silent mail loss - after a `250` this server owns the delivery
  or has to bounce it itself. The `550` makes the sender's MTA bounce to a
  human, who can resend to the lenient address alone.

## API Server

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_API_HOST` | `0.0.0.0` | API bind address |
| `FASTSMTP_API_PORT` | `8000` | API port |
| `FASTSMTP_CORS_ORIGINS` | *(empty)* | Allowed CORS origins. Empty leaves CORS middleware off entirely |

```bash
export FASTSMTP_CORS_ORIGINS='["https://console.example.com"]'
```

Credentials are allowed only for an explicit origin list. `["*"]` still works but
disables `allow_credentials`, since a wildcard origin with credentials is a
cross-origin read of anyone's session.

## Database

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_DATABASE_URL` | *required* | PostgreSQL or MariaDB connection URL |
| `FASTSMTP_DATABASE_POOL_SIZE` | `5` | Connection pool size |
| `FASTSMTP_DATABASE_POOL_MAX_OVERFLOW` | `10` | Max overflow connections |
| `FASTSMTP_DATABASE_ECHO` | `false` | Log every SQL statement. Development only - it logs query parameters |
| `FASTSMTP_VERIFY_SCHEMA_ON_STARTUP` | `true` | Refuse to start when the database is behind this build's migrations |

### Schema version check

Nothing applies migrations automatically -- `fastsmtp serve` does not run Alembic. On
startup the application compares the database's Alembic revision against the migrations
shipped in the image and refuses to start if the database is behind, naming both
revisions and the migrations that have not been applied.

This turns a missed `fastsmtp db upgrade head` into an immediate, explicit failure
instead of a `UndefinedColumn` error on the first query that touches a new column.

`fastsmtp db upgrade head` itself reads only `FASTSMTP_DATABASE_URL`: the migration
Job or pod does not need the root API key, the S3 settings, or anything else `serve`
requires.

A database *ahead* of the build is allowed, so a rolling deploy that migrates before the
old pods are gone does not take them down. A database with no `alembic_version` table
cannot be compared and is allowed with a warning.

## Retention

Two background jobs remove old rows. Both run on the same cleanup worker, which starts
with `fastsmtp serve` when **either** job is enabled.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_DELIVERY_LOG_RETENTION_DAYS` | `90` | Delivery-log rows older than this are deleted |
| `FASTSMTP_DELIVERY_LOG_CLEANUP_ENABLED` | `true` | Run the delivery-log job in the cleanup worker |
| `FASTSMTP_DELIVERY_LOG_CLEANUP_INTERVAL_HOURS` | `24` | How often the worker runs both jobs |
| `FASTSMTP_DELIVERY_LOG_CLEANUP_BATCH_SIZE` | `1000` | Delivery-log rows deleted per statement |
| `FASTSMTP_DELIVERY_LOG_CLEANUP_MAX_PER_RUN` | `100000` | Delivery-log rows deleted per run at most; the rest wait for the next run |
| `FASTSMTP_DELIVERY_LOG_CLEANUP_BATCH_DELAY_MS` | `100` | Pause between delivery-log batches, to spread database load |
| `FASTSMTP_SOFT_DELETE_RETENTION_DAYS` | - | Days a deleted user, API key, domain or recipient stays restorable before it is purged. Unset (the default) never purges automatically |

`DELETE` on a user, API key, domain or recipient is a **soft delete**: the row is
stamped, hidden and restorable - see
[Deletion, restore and purge](api.md#deletion-restore-and-purge). The soft-delete job
permanently removes rows whose stamp is older than
`FASTSMTP_SOFT_DELETE_RETENTION_DAYS`, running the same cascade as a manual purge: a
user takes its API keys and memberships, a domain its recipients, rulesets, rules and
members, and delivery-log rows survive with their `domain_id` / `recipient_id` cleared.
Each row is purged on its own clock - a recipient deleted before its domain goes first,
even if the domain is later restored.

Leaving the setting unset is deliberate: the first upgrade to v0.5.0 must not silently
schedule the destruction of everything that gets deleted afterwards. Set it once you have
decided how long a mistaken delete should stay reversible, e.g. `30`. The manual
equivalent is `fastsmtp purge-deleted`, which accepts `--dry-run` and an
`--older-than 30d` override.

```bash
export FASTSMTP_SOFT_DELETE_RETENTION_DAYS=30
```

The two jobs are independent: a failure in one is logged and does not skip the other,
and `FASTSMTP_DELIVERY_LOG_CLEANUP_ENABLED=false` with a soft-delete retention set still
starts the worker for the purge alone.

## Webhooks

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_WEBHOOK_TIMEOUT` | `30` | Request timeout (seconds) |
| `FASTSMTP_WEBHOOK_MAX_RETRIES` | `5` | Max retry attempts |
| `FASTSMTP_WEBHOOK_RETRY_BASE_DELAY` | `1.0` | Base delay for exponential backoff |
| `FASTSMTP_WEBHOOK_MAX_INLINE_ATTACHMENT_SIZE` | `10485760` | Max attachment size (bytes) for inline storage |
| `FASTSMTP_WEBHOOK_MAX_INLINE_PAYLOAD_SIZE` | `52428800` | Max total payload size (bytes) for inline storage |
| `FASTSMTP_WEBHOOK_ALLOWED_INTERNAL_DOMAINS` | *(empty)* | Hostnames (and their subdomains) allowed to bypass SSRF protection |

```bash
export FASTSMTP_WEBHOOK_ALLOWED_INTERNAL_DOMAINS='["n8n.svc.cluster.local"]'
```

An allowlisted entry bypasses **both** the private/internal IP-range check and the
blocked-hostname set (localhost, metadata aliases): FastSMTP trusts whatever IP the DNS
chain returns at connect time. Use it only for hostnames whose DNS infrastructure you
control. Because matching includes subdomains, a dangling DNS record under an allowlisted
parent is a takeover risk - prefer the most specific hostname. Entries are normalized
before matching: surrounding whitespace and a leading dot are stripped, case is ignored,
and empty entries are dropped.

## Dead Letter Queue

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_DLQ_WEBHOOK_URL` | - | Webhook notified when a delivery is exhausted. Unset means exhausted deliveries are only recorded in the delivery log |

When every retry of a delivery has failed, its status becomes `exhausted` and a
notification is posted to this URL with an `X-FastSMTP-Event: dlq` header and a payload
of the delivery's metadata, not the email itself:

```json
{
  "event": "delivery.exhausted",
  "delivery_id": "5f2c...",
  "message_id": "<abc123@sender.com>",
  "domain_id": "9a2e...",
  "webhook_url": "https://n8n.example.com/webhook/email",
  "attempts": 5,
  "last_error": "HTTP 502",
  "last_status_code": 502,
  "created_at": "2026-03-07T10:00:00+00:00",
  "exhausted_at": "2026-03-07T10:31:12+00:00"
}
```

The notification is fire-and-forget: a failure to reach the DLQ endpoint is logged and
changes nothing else. It goes through the same SSRF validation as any other webhook, so a
DLQ URL on an internal host needs `FASTSMTP_WEBHOOK_ALLOWED_INTERNAL_DOMAINS`. Deliveries
that end as `cancelled` never reach the DLQ - see
[Delivery statuses](webhooks.md#delivery-statuses).

## Queue Backpressure

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_QUEUE_MAX_PENDING` | - | Pending deliveries after which new mail is refused. Unset (the default) is unlimited |
| `FASTSMTP_QUEUE_BACKPRESSURE_ACTION` | `reject` | What to do once the limit is reached: `reject` or `drop` |

`reject` answers the SMTP transaction with `451 Service temporarily unavailable - queue
full, try again later`, which makes the sending MTA hold the message and retry. `drop`
answers `250` and discards the message; it protects the queue at the cost of losing mail
silently, so prefer `reject` unless you are absorbing a flood you would rather not have
retried at you.

Either way the message counts as `rejected` in
[`fastsmtp_smtp_messages_total`](monitoring.md#smtp-intake). Alert on
`fastsmtp_queue_depth{status="pending"}` before it reaches the limit rather than on the
rejections.

## Delivery Worker

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_WORKER_POLL_INTERVAL` | `1.0` | Seconds the worker waits before looking for work again when the queue is empty |
| `FASTSMTP_WORKER_BATCH_SIZE` | `10` | Deliveries claimed per poll |
| `FASTSMTP_INSTANCE_ID` | `$HOSTNAME` | Identifier this process claims deliveries under. Defaults to the hostname, or a random suffix when there is none |

Workers claim deliveries in the database, so several `fastsmtp serve --worker-only`
processes can run against one database without coordinating. `FASTSMTP_INSTANCE_ID` only
needs setting when two workers would otherwise share a hostname.

## Rate Limiting

Two independent limiters: the API one is shared across instances through Redis, the SMTP
one is per-process and in memory.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_REDIS_URL` | - | Redis/Valkey URL for API rate limiting, e.g. `redis://localhost:6379/0` |
| `FASTSMTP_RATE_LIMIT_ENABLED` | `true` | Enable API rate limiting. Has no effect without `FASTSMTP_REDIS_URL` |
| `FASTSMTP_RATE_LIMIT_REQUESTS_PER_MINUTE` | `100` | API requests per minute per API key |
| `FASTSMTP_RATE_LIMIT_AUTH_ATTEMPTS_PER_MINUTE` | `5` | Requests per minute per IP for requests with no usable `X-API-Key` header |

!!! warning "API rate limiting is off until Redis is configured"

    The middleware is only installed when `FASTSMTP_REDIS_URL` is set, so on a default
    deployment `FASTSMTP_RATE_LIMIT_REQUESTS_PER_MINUTE` does nothing. If Redis is
    configured but unreachable at request time, requests are allowed rather than
    refused - the limiter fails open.

`/metrics`, `/api/v1/health` and `/api/v1/ready` are excluded from API rate limiting.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_SMTP_RATE_LIMIT_ENABLED` | `true` | Enable SMTP rate limiting per client IP |
| `FASTSMTP_SMTP_RATE_LIMIT_CONNECTIONS_PER_MINUTE` | `30` | SMTP connections per minute per IP |
| `FASTSMTP_SMTP_RATE_LIMIT_MESSAGES_PER_MINUTE` | `60` | Messages per minute per IP |
| `FASTSMTP_SMTP_RATE_LIMIT_RECIPIENTS_PER_MESSAGE` | `100` | Recipients accepted per message; the next `RCPT TO` is answered `452 Too many recipients` |

SMTP limits need no Redis and are counted per process, so the effective limit for a
sender is the per-instance limit multiplied by the number of SMTP instances it can reach.
The recipient cap is the exception twice over: it counts the recipients of one
transaction, so it holds regardless of how many instances are running, and it is applied
even when `FASTSMTP_SMTP_RATE_LIMIT_ENABLED` is `false` - that flag only turns off the
per-IP connection and message buckets.
Refusals are counted in
[`fastsmtp_smtp_rate_limited_total`](monitoring.md#smtp-intake).

## Rule Engine

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_RULES_MAX_BODY_SIZE` | `1048576` | Size of the `body` field a rule sees (1 MB). Longer bodies are truncated for matching only |

The `body` field a rule matches against is the text and HTML parts joined together, and
it is this joined value that the limit truncates. Truncation is local to rule evaluation
and changes nothing about what is delivered: the webhook payload still carries the body,
subject to the webhook size settings above. A `contains` or `regex` rule can therefore
miss a match that sits past the cut-off. See [Rule Engine](rules.md).

## Attachment Storage (S3)

Store attachments in S3-compatible storage (AWS S3, MinIO, Ceph) instead of inline base64.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_ATTACHMENT_STORAGE` | `inline` | Storage backend: `inline` or `s3` |
| `FASTSMTP_S3_ENDPOINT_URL` | - | S3 endpoint (for MinIO/Ceph). Omit for AWS |
| `FASTSMTP_S3_BUCKET` | - | S3 bucket name (required when `s3`) |
| `FASTSMTP_S3_ACCESS_KEY` | - | S3 access key ID (required when `s3`) |
| `FASTSMTP_S3_SECRET_KEY` | - | S3 secret access key (required when `s3`) |
| `FASTSMTP_S3_REGION` | `us-east-1` | S3 region |
| `FASTSMTP_S3_PREFIX` | `attachments` | Key prefix for stored files |
| `FASTSMTP_S3_PRESIGNED_URLS` | `false` | Include presigned URLs in webhook payload |
| `FASTSMTP_S3_PRESIGNED_URL_EXPIRY` | `3600` | Presigned URL expiry (seconds) |

=== "AWS S3"

    ```bash
    export FASTSMTP_ATTACHMENT_STORAGE=s3
    export FASTSMTP_S3_BUCKET=my-email-attachments
    export FASTSMTP_S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
    export FASTSMTP_S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    export FASTSMTP_S3_REGION=us-west-2
    export FASTSMTP_S3_PRESIGNED_URLS=true
    ```

=== "MinIO"

    ```bash
    export FASTSMTP_ATTACHMENT_STORAGE=s3
    export FASTSMTP_S3_ENDPOINT_URL=http://minio:9000
    export FASTSMTP_S3_BUCKET=attachments
    export FASTSMTP_S3_ACCESS_KEY=minioadmin
    export FASTSMTP_S3_SECRET_KEY=minioadmin
    export FASTSMTP_S3_PRESIGNED_URLS=true
    ```

## Raw Message Preservation (S3)

Archive the complete raw MIME message (headers, bodies and attachments exactly as
received) alongside webhook delivery. Preservation reuses the S3 credentials above and
works whether attachments are stored inline or in S3.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_PRESERVE_RAW_MESSAGE` | `false` | Default for domains that do not override it |
| `FASTSMTP_PRESERVE_RAW_REQUIRED` | `false` | Reject the message with `451` if archiving fails |
| `FASTSMTP_S3_RAW_PREFIX` | `raw` | Key prefix for preserved messages |

Objects are stored as `message/rfc822` under
`{prefix}/{domain}/{YYYY}/{MM}/{DD}/{message-id}.eml`, so S3 lifecycle rules can expire
archives by age.

Preservation is decided per recipient, from three sources in order:

1. A matching rule with `preserve_raw: true` - always enables it, independent of the
   rule's action, so a rule can archive a message and still drop it.
2. The domain's `preserve_raw_message` - `true` or `false` overrides the global default.
3. The global `FASTSMTP_PRESERVE_RAW_MESSAGE` setting, used when the domain leaves it unset.

A message is uploaded at most once no matter how many recipients ask for it. When it is
preserved, the webhook payload gains a `raw_message` block:

```json
{
  "raw_message": {
    "storage": "s3",
    "bucket": "my-email-archive",
    "key": "raw/example.com/2026/03/07/abc123@example.com.eml",
    "url": "https://s3.us-west-2.amazonaws.com/my-email-archive/raw/...",
    "size": 48213,
    "presigned_url": "https://..."
  }
}
```

By default an upload failure is logged and delivery continues. Set
`FASTSMTP_PRESERVE_RAW_REQUIRED=true` to treat the archive as mandatory instead: the SMTP
transaction is rolled back and answered with a temporary failure so the sender retries.

```bash
export FASTSMTP_S3_BUCKET=my-email-archive
export FASTSMTP_S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
export FASTSMTP_S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export FASTSMTP_S3_REGION=us-west-2
export FASTSMTP_PRESERVE_RAW_MESSAGE=true
```

!!! note "Validation"

    The API rejects enabling `preserve_raw_message` on a domain or `preserve_raw` on a
    rule with `422` when S3 is not configured, so a flag can never be stored that would
    silently do nothing.

## Metrics Endpoint Access

`GET /metrics` is unauthenticated and excluded from rate limiting. These settings
restrict who may scrape it. Both accept bare addresses and CIDR prefixes, in
either address family, and malformed entries are rejected at startup.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_METRICS_ALLOWED_IPS` | *(empty)* | Addresses allowed to scrape `/metrics`. Empty leaves it unrestricted |
| `FASTSMTP_METRICS_TRUSTED_PROXIES` | *(empty)* | Proxies whose `X-Forwarded-For` may be trusted. Empty means the header is never trusted |

```bash
export FASTSMTP_METRICS_ALLOWED_IPS='["10.0.0.0/8","192.0.2.5"]'
```

See [Monitoring](monitoring.md) for the metric reference, scrape configuration,
and the reverse-proxy caveats.

## Security

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_ROOT_API_KEY` | *required* | Root API key for superuser access. Required by `fastsmtp serve`; not read by `fastsmtp db` |
| `FASTSMTP_API_KEY_HASH_ALGORITHM` | `sha256` | Legacy fallback used only to verify unsalted keys issued by older versions |

The root API key is compared in constant time and is never stored in the database. Issued
keys are stored as a salted PBKDF2-HMAC-SHA256 hash and never in clear, so
`FASTSMTP_API_KEY_HASH_ALGORITHM` has no effect on keys created by any current version -
it only decides how a pre-salting key is verified, and changing it stops those keys from
authenticating. Rotate the remaining unsalted keys (`fsmtp auth rotate-key`) rather than
touching it.

## Webhook Header Encryption

`recipients.webhook_headers` holds the customer's own bearer tokens for their webhook
endpoint. Configuring a key encrypts that column at rest, so a stolen database or backup
does not hand over those credentials. It is a storage-layer feature only: API responses,
payload shapes and CLI output are unchanged either way, and an authorised API caller can
still read the headers back through the ordinary API - this defends the data at rest, not
from the people already allowed to read it through the application.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_ENCRYPTION_KEYS` | *(empty)* | Keys in priority order. The first key encrypts; every key is tried when decrypting. Empty means the column is stored in clear, exactly as before |
| `FASTSMTP_VERIFY_ENCRYPTION_ON_STARTUP` | `true` | Refuse to start when the database holds encrypted rows and no key is configured |

It is a JSON list in the environment, the same shape as `FASTSMTP_METRICS_ALLOWED_IPS`:

```bash
export FASTSMTP_ENCRYPTION_KEYS='["your-key"]'
```

Generate the key rather than choosing a memorable one:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Any string is accepted and is stretched with PBKDF2-HMAC-SHA256 at 100,000 iterations -
the same work factor used for API key hashes - but the salt is fixed, because the
derivation has to be reproducible from the key alone with no per-deployment state to
store. A generated key has enough entropy that the fixed salt does not matter; a
memorable one would not.

!!! warning "Losing the key loses the data"

    There is no recovery path. A key removed from `FASTSMTP_ENCRYPTION_KEYS` before every
    row written under it has been re-encrypted makes those rows permanently unreadable.
    Keys belong in the same place as `FASTSMTP_ROOT_API_KEY`.

### Rollout

1. Generate a key, set `FASTSMTP_ENCRYPTION_KEYS`, restart. New writes are encrypted.
2. Run `fastsmtp encrypt-existing` to convert the rows already there - see
   [Maintenance](cli/fastsmtp.md#maintenance).

Existing rows do **not** convert through ordinary traffic. SQLAlchemy emits no UPDATE
when a value is written back equal to what was loaded, and in-place mutation of the
dict is not tracked at all, so a recipient nobody edits keeps plaintext headers
indefinitely. The backfill command is what carries the rollout, not time.

### Rotation

!!! warning "Getting this order wrong destroys data"

    1. Prepend the new key while keeping the old one: `'["new-key", "old-key"]'`
    2. Restart, so new writes use the new key.
    3. Run `fastsmtp encrypt-existing`, which rewrites every row under the new key.
    4. Only now remove the old key.

    Dropping the old key before step 3 finishes makes every row still written under it
    permanently unreadable. The command refuses to overwrite a row it cannot decrypt and
    exits non-zero, so it will tell you before that happens - but it cannot undo an old
    key that has already been removed.

No migration is needed to adopt this feature: the ciphertext is wrapped in a JSON
envelope, so the column stays `JSONB` (PostgreSQL) or `JSON` (elsewhere) and the schema
is unchanged. Upgrading needs no `fastsmtp db upgrade` on its account.

The startup guard behind `FASTSMTP_VERIFY_ENCRYPTION_ON_STARTUP` covers `fastsmtp serve`
in every mode, including `--worker-only`, and refuses to boot rather than failing on the
first row it cannot decrypt.
