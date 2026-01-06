# FastSMTP

A TLS-capable, async SMTP server that receives emails and forwards them to webhooks. Built with Python 3.12+ for integration with n8n and other webhook-based workflow platforms.

## Features

- **SMTP Server**: Dual-port support (plain SMTP and TLS), STARTTLS with optional enforcement
- **Email Authentication**: DKIM and SPF verification with configurable enforcement
- **Webhook Delivery**: Reliable delivery queue with exponential backoff retry logic
- **Rule Engine**: Conditional routing based on email attributes (from, to, subject, headers, etc.)
- **REST API**: Full management API with OpenAPI documentation
- **Multi-tenant**: Domain-based isolation with role-based access control
- **Horizontal Scaling**: Stateless design with database-backed task distribution

## Quick Start

### Prerequisites

- Python 3.12+
- PostgreSQL 16+ (or MariaDB 10.6+)
- uv (recommended) or pip

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/fastsmtp.git
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

### Docker Compose

```yaml
version: "3.8"
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: fastsmtp
      POSTGRES_USER: fastsmtp
      POSTGRES_PASSWORD: fastsmtp
    volumes:
      - postgres_data:/var/lib/postgresql/data

  fastsmtp:
    build: .
    ports:
      - "8000:8000"   # API
      - "2525:2525"   # SMTP
      - "4650:4650"   # SMTP TLS
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@db/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY}
    depends_on:
      - db

  worker:
    build: .
    command: fastsmtp serve --worker-only
    environment:
      FASTSMTP_DATABASE_URL: postgresql+asyncpg://fastsmtp:fastsmtp@db/fastsmtp
      FASTSMTP_ROOT_API_KEY: ${FASTSMTP_ROOT_API_KEY}
    depends_on:
      - db

volumes:
  postgres_data:
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

When an email is received, FastSMTP sends a POST request to the configured webhook:

```json
{
  "message_id": "<unique-id@domain.com>",
  "from": "sender@example.com",
  "to": "recipient@yourdomain.com",
  "subject": "Email Subject",
  "date": "Mon, 06 Jan 2025 10:00:00 +0000",
  "envelope_from": "sender@example.com",
  "envelope_to": ["recipient@yourdomain.com"],
  "headers": {
    "From": "sender@example.com",
    "To": "recipient@yourdomain.com",
    "Subject": "Email Subject"
  },
  "body_text": "Plain text content",
  "body_html": "<html>HTML content</html>",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "document.pdf",
      "content_type": "application/pdf",
      "size": 12345
    }
  ],
  "dkim_result": "pass",
  "dkim_domain": "example.com",
  "spf_result": "pass",
  "spf_domain": "example.com",
  "client_ip": "192.168.1.100",
  "tags": ["important"]
}
```

## CLI Usage

### Server CLI

```bash
# Start all services
fastsmtp serve

# Start only SMTP server
fastsmtp serve --smtp-only

# Start only API server
fastsmtp serve --api-only

# Start only webhook worker
fastsmtp serve --worker-only

# Database migrations
fastsmtp db upgrade
fastsmtp db downgrade
fastsmtp db current

# User management
fastsmtp user create admin admin@example.com
fastsmtp user list
fastsmtp user set-superuser admin
fastsmtp user generate-key admin

# Domain management
fastsmtp domain create example.com
fastsmtp domain add-member example.com admin --role owner
```

### Remote CLI

The `fsmtp` command provides remote management:

```bash
# Configure profile
fsmtp config set-url https://fastsmtp.example.com
fsmtp config set-api-key your-api-key

# Domain operations
fsmtp domain list
fsmtp domain create example.com

# Recipient management
fsmtp recipient list example.com
fsmtp recipient create example.com support https://webhook.site/xxx

# Check health
fsmtp ops health
```

## Rule Engine

Rules allow conditional processing of emails:

```bash
# Create a ruleset
fsmtp rules ruleset create example.com "Spam Filter" --priority 10

# Add a rule to tag spam
fsmtp rules rule create example.com <ruleset-id> \
  --field subject \
  --operator contains \
  --value "[SPAM]" \
  --action tag \
  --action-value spam

# Add a rule to forward to different webhook
fsmtp rules rule create example.com <ruleset-id> \
  --field from \
  --operator equals \
  --value "vip@important.com" \
  --action forward \
  --webhook-override https://special-webhook.example.com/vip
```

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

MIT License - see LICENSE file for details.
