# Configuration

All configuration is via environment variables with the `FASTSMTP_` prefix.

## SMTP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_SMTP_HOST` | `0.0.0.0` | SMTP bind address |
| `FASTSMTP_SMTP_PORT` | `2525` | Plain SMTP port |
| `FASTSMTP_SMTP_TLS_PORT` | `4650` | TLS SMTP port |
| `FASTSMTP_SMTP_TLS_CERT` | - | Path to TLS certificate |
| `FASTSMTP_SMTP_TLS_KEY` | - | Path to TLS private key |
| `FASTSMTP_SMTP_REQUIRE_STARTTLS` | `false` | Enforce STARTTLS |

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
time. Set them with `fsmtp domain create/update` or `PUT /domains/{id}`.

Two rules make this predictable when a message has recipients on more than one
domain:

- A check runs once for the message if **any** recipient's domain verifies that
  mechanism, and the result is recorded for every recipient. A domain that sets
  `verify_dkim` to `false` never rejects on DKIM and never sees a DKIM decision of
  its own.
- A domain can only reject on a mechanism it also verifies. If only some
  recipients' domains reject the message, it is accepted (`250`) and those
  recipients get no delivery; it is refused with `550 DKIM verification failed`
  or `550 SPF verification failed` only when every recipient refuses it.

## API Server

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_API_HOST` | `0.0.0.0` | API bind address |
| `FASTSMTP_API_PORT` | `8000` | API port |

## Database

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_DATABASE_URL` | *required* | PostgreSQL or MariaDB connection URL |
| `FASTSMTP_DATABASE_POOL_SIZE` | `5` | Connection pool size |
| `FASTSMTP_DATABASE_POOL_MAX_OVERFLOW` | `10` | Max overflow connections |
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
