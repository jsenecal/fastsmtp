# FastSMTP

A TLS-capable, async SMTP server that receives emails and forwards them to webhooks. Built with Python 3.12+ for integration with n8n and other webhook-based workflow platforms.

## Features

- **SMTP Server**: Dual-port support (plain SMTP and TLS), STARTTLS with optional enforcement, hot-reload TLS certificates
- **Email Authentication**: DKIM and SPF verification with configurable enforcement
- **Webhook Delivery**: Reliable delivery queue with exponential backoff retry, dead letter queue (DLQ) notifications
- **S3 Attachment Storage**: Optional S3-compatible storage (AWS S3, MinIO, Ceph) with presigned URL support
- **Rule Engine**: Conditional routing based on email attributes (from, to, subject, headers, etc.)
- **REST API**: Full management API with OpenAPI documentation
- **Multi-tenant**: Domain-based isolation with role-based access control
- **Rate Limiting**: Configurable limits for both API and SMTP (per-IP connection/message limits)
- **Security**: Webhook header encryption at rest, SSRF protection for webhook URLs
- **Queue Backpressure**: Configurable limits to prevent unbounded queue growth
- **Automatic Cleanup**: Background worker for delivery log retention management
- **Horizontal Scaling**: Stateless design with database-backed task distribution

## Quick Start

### Prerequisites

- Python 3.12+
- PostgreSQL 16+ (or MariaDB 10.6+)
- uv (recommended) or pip

### Installation

```bash
# Clone the repository
git clone https://github.com/jsenecal/fastsmtp.git
cd fastsmtp

# Install dependencies
uv sync

# Set up environment
export FASTSMTP_DATABASE_URL="postgresql+asyncpg://user:pass@localhost/fastsmtp"
export FASTSMTP_ROOT_API_KEY="your-secure-root-key"

# Run database migrations
uv run fastsmtp db upgrade

# Start the server
uv run fastsmtp serve
```

### Docker

```bash
# Pull the image
docker pull ghcr.io/jsenecal/fastsmtp:v0.1.1

# Run with required environment variables
docker run -d \
  -p 8000:8000 -p 2525:2525 -p 4650:4650 \
  -e FASTSMTP_DATABASE_URL="postgresql+asyncpg://user:pass@host/fastsmtp" \
  -e FASTSMTP_ROOT_API_KEY="your-secure-key" \
  ghcr.io/jsenecal/fastsmtp:v0.1.1
```

### Docker Compose

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: fastsmtp
      POSTGRES_USER: fastsmtp
      POSTGRES_PASSWORD: fastsmtp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fastsmtp"]
      interval: 5s
      timeout: 5s
      retries: 5

  fastsmtp:
    image: ghcr.io/jsenecal/fastsmtp:v0.1.1
    ports:
      - "8000:8000"   # API
      - "2525:2525"   # SMTP
      - "4650:4650"   # SMTP TLS
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
      FASTSMTP_API_HOST: 0.0.0.0
      FASTSMTP_SMTP_HOST: 0.0.0.0
    depends_on:
      postgres:
        condition: service_healthy

  worker:
    image: ghcr.io/jsenecal/fastsmtp:v0.1.1
    command: ["fastsmtp", "serve", "--worker-only"]
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
    depends_on:
      postgres:
        condition: service_healthy
    deploy:
      replicas: 2

volumes:
  postgres_data:
```

### Docker Compose with S3 (MinIO)

For attachment storage with MinIO:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: fastsmtp
      POSTGRES_USER: fastsmtp
      POSTGRES_PASSWORD: fastsmtp
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U fastsmtp"]
      interval: 5s
      timeout: 5s
      retries: 5

  minio:
    image: minio/minio:latest
    command: server /data --console-address ":9001"
    ports:
      - "9000:9000"
      - "9001:9001"
    environment:
      MINIO_ROOT_USER: minioadmin
      MINIO_ROOT_PASSWORD: minioadmin
    volumes:
      - minio_data:/data
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 5s
      timeout: 5s
      retries: 5

  createbucket:
    image: minio/mc:latest
    depends_on:
      minio:
        condition: service_healthy
    entrypoint: >
      /bin/sh -c "
      mc alias set myminio http://minio:9000 minioadmin minioadmin;
      mc mb --ignore-existing myminio/attachments;
      exit 0;
      "

  fastsmtp:
    image: ghcr.io/jsenecal/fastsmtp:v0.1.1
    ports:
      - "8000:8000"
      - "2525:2525"
      - "4650:4650"
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
      FASTSMTP_API_HOST: 0.0.0.0
      FASTSMTP_SMTP_HOST: 0.0.0.0
      FASTSMTP_ATTACHMENT_STORAGE: s3
      FASTSMTP_S3_ENDPOINT_URL: http://minio:9000
      FASTSMTP_S3_BUCKET: attachments
      FASTSMTP_S3_ACCESS_KEY: minioadmin
      FASTSMTP_S3_SECRET_KEY: minioadmin
      FASTSMTP_S3_PRESIGNED_URLS: "true"
    depends_on:
      postgres:
        condition: service_healthy
      createbucket:
        condition: service_completed_successfully

  worker:
    image: ghcr.io/jsenecal/fastsmtp:v0.1.1
    command: ["fastsmtp", "serve", "--worker-only"]
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@postgres/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY:?Required}
      FASTSMTP_ATTACHMENT_STORAGE: s3
      FASTSMTP_S3_ENDPOINT_URL: http://minio:9000
      FASTSMTP_S3_BUCKET: attachments
      FASTSMTP_S3_ACCESS_KEY: minioadmin
      FASTSMTP_S3_SECRET_KEY: minioadmin
    depends_on:
      postgres:
        condition: service_healthy
    deploy:
      replicas: 2

volumes:
  postgres_data:
  minio_data:
```

## Configuration

All configuration is via environment variables with the `FASTSMTP_` prefix.

### SMTP Server

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_SMTP_HOST` | `0.0.0.0` | SMTP bind address |
| `FASTSMTP_SMTP_PORT` | `2525` | Plain SMTP port |
| `FASTSMTP_SMTP_TLS_PORT` | `4650` | TLS SMTP port |
| `FASTSMTP_SMTP_TLS_CERT` | - | Path to TLS certificate |
| `FASTSMTP_SMTP_TLS_KEY` | - | Path to TLS private key |
| `FASTSMTP_SMTP_REQUIRE_STARTTLS` | `false` | Enforce STARTTLS |

### Email Validation

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_SMTP_VERIFY_DKIM` | `true` | Enable DKIM verification |
| `FASTSMTP_SMTP_VERIFY_SPF` | `true` | Enable SPF verification |
| `FASTSMTP_SMTP_REJECT_DKIM_FAIL` | `false` | Reject emails on DKIM failure |
| `FASTSMTP_SMTP_REJECT_SPF_FAIL` | `false` | Reject emails on SPF failure |

### API Server

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_API_HOST` | `0.0.0.0` | API bind address |
| `FASTSMTP_API_PORT` | `8000` | API port |

### Database

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_DATABASE_URL` | *required* | PostgreSQL or MariaDB connection URL |
| `FASTSMTP_DATABASE_POOL_SIZE` | `5` | Connection pool size |
| `FASTSMTP_DATABASE_POOL_MAX_OVERFLOW` | `10` | Max overflow connections |

### Webhooks

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_WEBHOOK_TIMEOUT` | `30` | Request timeout (seconds) |
| `FASTSMTP_WEBHOOK_MAX_RETRIES` | `5` | Max retry attempts |
| `FASTSMTP_WEBHOOK_RETRY_BASE_DELAY` | `1.0` | Base delay for exponential backoff |
| `FASTSMTP_WEBHOOK_MAX_INLINE_ATTACHMENT_SIZE` | `10485760` | Max attachment size (bytes) for inline storage |
| `FASTSMTP_WEBHOOK_MAX_INLINE_PAYLOAD_SIZE` | `52428800` | Max total payload size (bytes) for inline storage |

### Attachment Storage (S3)

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

**Example: AWS S3**
```bash
export FASTSMTP_ATTACHMENT_STORAGE=s3
export FASTSMTP_S3_BUCKET=my-email-attachments
export FASTSMTP_S3_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
export FASTSMTP_S3_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
export FASTSMTP_S3_REGION=us-west-2
export FASTSMTP_S3_PRESIGNED_URLS=true
```

**Example: MinIO**
```bash
export FASTSMTP_ATTACHMENT_STORAGE=s3
export FASTSMTP_S3_ENDPOINT_URL=http://minio:9000
export FASTSMTP_S3_BUCKET=attachments
export FASTSMTP_S3_ACCESS_KEY=minioadmin
export FASTSMTP_S3_SECRET_KEY=minioadmin
export FASTSMTP_S3_PRESIGNED_URLS=true
```

### Security

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_ROOT_API_KEY` | *required* | Root API key for superuser access |

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Email Client  │────▶│   SMTP Server   │────▶│    Database     │
└─────────────────┘     │  (ports 2525,   │     │   (PostgreSQL)  │
                        │   4650 TLS)     │     └────────┬────────┘
                        └─────────────────┘              │
                                                         │
┌─────────────────┐     ┌─────────────────┐              │
│   API Clients   │────▶│   REST API      │◀─────────────┤
│   (CLI, Web)    │     │  (port 8000)    │              │
└─────────────────┘     └─────────────────┘              │
                                                         │
                        ┌─────────────────┐              │
                        │ Webhook Worker  │◀─────────────┘
                        │  (background)   │────▶ Webhook Endpoints
                        └─────────────────┘
```

### Email Flow

1. Client connects to SMTP server
2. Server validates recipient against configured domains
3. Email is received and parsed (headers, body, attachments)
4. DKIM and SPF verification runs in parallel
5. Rules are evaluated to determine routing
6. Email is queued for webhook delivery
7. Worker delivers to webhook with retry logic

## API Reference

Base URL: `/api/v1`

### Authentication

All API requests require an API key in the header:

```bash
curl -H "X-API-Key: your-api-key" https://fastsmtp.example.com/api/v1/domains
```

### Endpoints

#### Operations
- `GET /health` - Health check
- `GET /ready` - Readiness check (database connectivity)
- `POST /test-webhook` - Test a webhook URL

#### Domains
- `GET /domains` - List domains
- `POST /domains` - Create domain
- `GET /domains/{id}` - Get domain
- `PUT /domains/{id}` - Update domain
- `DELETE /domains/{id}` - Delete domain

#### Recipients
- `GET /domains/{id}/recipients` - List recipients
- `POST /domains/{id}/recipients` - Create recipient
- `PUT /domains/{id}/recipients/{rid}` - Update recipient
- `DELETE /domains/{id}/recipients/{rid}` - Delete recipient

#### Rules
- `GET /domains/{id}/rulesets` - List rulesets
- `POST /domains/{id}/rulesets` - Create ruleset
- `POST /domains/{id}/rulesets/{rsid}/rules` - Create rule

#### Delivery Logs
- `GET /domains/{id}/delivery-log` - List delivery logs
- `GET /delivery-log/{id}` - Get delivery log details
- `POST /delivery-log/{id}/retry` - Retry failed delivery

Full API documentation available at `/docs` (Swagger UI) or `/redoc`.

## Webhook Payload

When an email is received, FastSMTP sends a POST request to the configured webhook. The payload structure depends on your attachment storage configuration.

### Inline Storage (Default)

With `FASTSMTP_ATTACHMENT_STORAGE=inline` (default), attachments are base64-encoded directly in the payload:

```json
{
  "message_id": "<abc123@sender.com>",
  "from": "sender@example.com",
  "to": "recipient@yourdomain.com",
  "subject": "Invoice for January",
  "date": "Mon, 06 Jan 2025 10:00:00 +0000",
  "envelope_from": "sender@example.com",
  "envelope_to": ["recipient@yourdomain.com"],
  "headers": {
    "From": "John Doe <sender@example.com>",
    "To": "recipient@yourdomain.com",
    "Subject": "Invoice for January",
    "Content-Type": "multipart/mixed"
  },
  "body_text": "Please find attached the invoice for January 2025.",
  "body_html": "<p>Please find attached the invoice for January 2025.</p>",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "size": 45678,
      "content": "JVBERi0xLjQKJeLjz9MKMyAwIG9iago8PC9UeXBlL..."
    }
  ],
  "dkim_result": "pass",
  "dkim_domain": "example.com",
  "spf_result": "pass",
  "spf_domain": "example.com",
  "client_ip": "203.0.113.50",
  "tags": []
}
```

### S3 Storage

With `FASTSMTP_ATTACHMENT_STORAGE=s3`, attachments are uploaded to S3 and the payload contains bucket/key references:

```json
{
  "message_id": "<abc123@sender.com>",
  "from": "sender@example.com",
  "to": "recipient@yourdomain.com",
  "subject": "Invoice for January",
  "date": "Mon, 06 Jan 2025 10:00:00 +0000",
  "envelope_from": "sender@example.com",
  "envelope_to": ["recipient@yourdomain.com"],
  "headers": {
    "From": "John Doe <sender@example.com>",
    "To": "recipient@yourdomain.com",
    "Subject": "Invoice for January"
  },
  "body_text": "Please find attached the invoice for January 2025.",
  "body_html": "<p>Please find attached the invoice for January 2025.</p>",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "size": 45678,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf"
    }
  ],
  "dkim_result": "pass",
  "dkim_domain": "example.com",
  "spf_result": "pass",
  "spf_domain": "example.com",
  "client_ip": "203.0.113.50",
  "tags": []
}
```

### S3 Storage with Presigned URLs

With `FASTSMTP_S3_PRESIGNED_URLS=true`, the payload includes time-limited download URLs:

```json
{
  "message_id": "<abc123@sender.com>",
  "from": "sender@example.com",
  "to": "recipient@yourdomain.com",
  "subject": "Invoice for January",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "size": 45678,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf",
      "presigned_url": "https://my-email-attachments.s3.us-west-2.amazonaws.com/attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20250106%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250106T100000Z&X-Amz-Expires=3600&X-Amz-Signature=abc123..."
    }
  ]
}
```

### S3 Fallback to Inline

If S3 upload fails, FastSMTP gracefully falls back to inline storage. The attachment will have `storage_fallback: true` to indicate this:

```json
{
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "size": 45678,
      "storage_fallback": true,
      "content": "JVBERi0xLjQKJeLjz9MKMyAwIG9iago8PC9UeXBlL..."
    }
  ]
}
```

### Multiple Attachments Example

```json
{
  "message_id": "<xyz789@sender.com>",
  "from": "hr@company.com",
  "to": "onboarding@yourdomain.com",
  "subject": "New Employee Documents",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "offer-letter.pdf",
      "content_type": "application/pdf",
      "size": 89012,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/offer-letter.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/offer-letter.pdf",
      "presigned_url": "https://..."
    },
    {
      "filename": "headshot.jpg",
      "content_type": "image/jpeg",
      "size": 234567,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/headshot.jpg",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/headshot.jpg",
      "presigned_url": "https://..."
    },
    {
      "filename": "w4-form.pdf",
      "content_type": "application/pdf",
      "size": 56789,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/w4-form.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/w4-form.pdf",
      "presigned_url": "https://..."
    }
  ]
}
```

### S3 Key Structure

Attachments are stored with the following key structure:
```
{prefix}/{domain}/{message_id}/{filename}
```

For example:
```
attachments/yourdomain.com/abc123@sender.com/invoice.pdf
```

## CLI Reference

FastSMTP provides two CLI tools:

- **`fastsmtp`** - Server-side CLI for running the server and administration
- **`fsmtp`** - Remote CLI client for managing FastSMTP from anywhere

### Server CLI (`fastsmtp`)

The server CLI is used to run the FastSMTP server and perform local administration tasks.

#### Starting the Server

```bash
# Start all services (SMTP, API, webhook worker)
fastsmtp serve

# Start individual components (for horizontal scaling)
fastsmtp serve --smtp-only      # Only SMTP server
fastsmtp serve --api-only       # Only REST API
fastsmtp serve --worker-only    # Only webhook worker

# Custom shutdown timeout
fastsmtp serve --shutdown-timeout 60
```

#### Database Management

```bash
# Apply all pending migrations
fastsmtp db upgrade

# Upgrade to specific revision
fastsmtp db upgrade abc123

# Rollback one migration
fastsmtp db downgrade -1

# Show current revision
fastsmtp db current

# Show migration history
fastsmtp db history

# Create new migration (development)
fastsmtp db revision -m "Add new table"
```

#### User Management

```bash
# Create a new user
fastsmtp user create alice alice@example.com

# List all users
fastsmtp user list

# Grant superuser privileges
fastsmtp user set-superuser alice

# Revoke superuser privileges
fastsmtp user set-superuser alice --revoke

# Generate API key for user
fastsmtp user generate-key alice

# Delete a user
fastsmtp user delete alice
```

#### Domain Management

```bash
# Create a domain
fastsmtp domain create example.com

# List all domains
fastsmtp domain list

# Add a member to domain
fastsmtp domain add-member example.com alice --role owner
fastsmtp domain add-member example.com bob --role admin
fastsmtp domain add-member example.com charlie --role member

# Remove member from domain
fastsmtp domain remove-member example.com charlie

# Delete a domain
fastsmtp domain delete example.com
```

#### Maintenance

```bash
# Clean up old delivery logs (respects retention settings)
fastsmtp cleanup

# Preview what would be deleted
fastsmtp cleanup --dry-run

# Override retention period
fastsmtp cleanup --older-than 30d

# Show current configuration
fastsmtp show-config

# Show version
fastsmtp version
```

### Remote CLI (`fsmtp`)

The remote CLI connects to a FastSMTP server over HTTPS for remote management.

#### Configuration

```bash
# Initialize configuration interactively
fsmtp config init

# Create/update a profile
fsmtp config set myprofile \
  --url https://fastsmtp.example.com \
  --api-key "your-api-key"

# Set default profile
fsmtp config use myprofile

# Show current configuration
fsmtp config show

# Delete a profile
fsmtp config delete myprofile
```

#### Authentication

```bash
# Show current user info
fsmtp auth whoami

# List your API keys
fsmtp auth keys

# Create a new API key
fsmtp auth create-key --name "CI/CD"

# Rotate an API key
fsmtp auth rotate-key <key-id>

# Delete an API key
fsmtp auth delete-key <key-id>
```

#### Domain Management

```bash
# List domains you have access to
fsmtp domain list

# Get domain details
fsmtp domain get example.com

# Create a new domain
fsmtp domain create example.com

# Update domain settings
fsmtp domain update example.com --description "Production domain"

# Delete a domain
fsmtp domain delete example.com

# Manage domain members
fsmtp domain member list example.com
fsmtp domain member add example.com alice@example.com --role admin
fsmtp domain member remove example.com alice@example.com
```

#### Recipient Management

```bash
# List recipients for a domain
fsmtp recipient list example.com

# Get recipient details
fsmtp recipient get example.com support

# Create a recipient with webhook
fsmtp recipient create example.com support \
  --webhook-url https://n8n.example.com/webhook/email

# Update recipient
fsmtp recipient update example.com support \
  --webhook-url https://new-webhook.example.com/email

# Delete recipient
fsmtp recipient delete example.com support
```

#### Rule Management

```bash
# List rulesets for a domain
fsmtp rules list example.com

# Get ruleset with all rules
fsmtp rules get example.com <ruleset-id>

# Create a ruleset
fsmtp rules create example.com "Spam Filter" --priority 10

# Update ruleset
fsmtp rules update example.com <ruleset-id> --priority 20

# Delete ruleset
fsmtp rules delete example.com <ruleset-id>

# Create a rule within a ruleset
fsmtp rules rule create example.com <ruleset-id> \
  --field subject \
  --operator contains \
  --value "[SPAM]" \
  --action tag \
  --action-value spam

# Update a rule
fsmtp rules rule update example.com <ruleset-id> <rule-id> \
  --action drop

# Delete a rule
fsmtp rules rule delete example.com <ruleset-id> <rule-id>
```

#### Operations

```bash
# Check server health
fsmtp ops health

# Check server readiness (includes DB)
fsmtp ops ready

# Test a webhook URL
fsmtp ops test-webhook https://webhook.site/xxx

# View delivery logs
fsmtp ops log list example.com
fsmtp ops log list example.com --status failed --limit 50

# Get delivery log details
fsmtp ops log get <log-id>

# Retry a failed delivery
fsmtp ops log retry <log-id>
```

## Rule Engine

The rule engine allows conditional processing of emails based on various attributes.

### Rule Fields
- `from`, `to`, `cc`, `subject`, `body`
- `header:<name>` (e.g., `header:X-Priority`)
- `has_attachments`, `attachment_count`
- `dkim_result`, `spf_result`

### Rule Operators
- `equals`, `not_equals`
- `contains`, `not_contains`
- `starts_with`, `ends_with`
- `matches` (regex)
- `greater_than`, `less_than` (for numeric fields)

### Rule Actions
- `tag` - Add a tag to the email
- `forward` - Forward to webhook (can override URL)
- `drop` - Silently drop the email
- `quarantine` - Mark as quarantined

## Development

```bash
# Install dev dependencies
uv sync --dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=fastsmtp --cov-report=term-missing

# Lint and format
uv run ruff check .
uv run ruff format .
```

## License

AGPL-3.0 - see [LICENSE](LICENSE) file for details.
