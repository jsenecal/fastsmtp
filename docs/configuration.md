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

## Webhooks

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_WEBHOOK_TIMEOUT` | `30` | Request timeout (seconds) |
| `FASTSMTP_WEBHOOK_MAX_RETRIES` | `5` | Max retry attempts |
| `FASTSMTP_WEBHOOK_RETRY_BASE_DELAY` | `1.0` | Base delay for exponential backoff |
| `FASTSMTP_WEBHOOK_MAX_INLINE_ATTACHMENT_SIZE` | `10485760` | Max attachment size (bytes) for inline storage |
| `FASTSMTP_WEBHOOK_MAX_INLINE_PAYLOAD_SIZE` | `52428800` | Max total payload size (bytes) for inline storage |

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

1. A matching rule with `preserve_raw: true` — always enables it, independent of the
   rule's action, so a rule can archive a message and still drop it.
2. The domain's `preserve_raw_message` — `true` or `false` overrides the global default.
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
| `FASTSMTP_ROOT_API_KEY` | *required* | Root API key for superuser access |
