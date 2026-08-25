# FastSMTP

[![CI](https://github.com/jsenecal/fastsmtp/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/jsenecal/fastsmtp/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/jsenecal/fastsmtp/branch/main/graph/badge.svg)](https://codecov.io/gh/jsenecal/fastsmtp)
[![Release](https://img.shields.io/github/v/release/jsenecal/fastsmtp)](https://github.com/jsenecal/fastsmtp/releases/latest)
[![PyPI](https://img.shields.io/pypi/v/fastsmtp)](https://pypi.org/project/fastsmtp/)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-fastsmtp-2496ED?logo=docker&logoColor=white)](https://github.com/jsenecal/fastsmtp/pkgs/container/fastsmtp)
[![License: AGPL-3.0-or-later](https://img.shields.io/badge/license-AGPL--3.0--or--later-blue.svg)](LICENSE)

A TLS-capable, async SMTP server that receives emails and forwards them to webhooks.
Built with Python 3.12+ for integration with n8n and other webhook-based workflow
platforms.

**Documentation: <https://jsenecal.github.io/fastsmtp/>**

## Features

- **SMTP Server**: Dual-port support (plain SMTP and TLS), STARTTLS with optional enforcement, hot-reload TLS certificates
- **Email Authentication**: DKIM and SPF verification with configurable enforcement, overridable per domain
- **Webhook Delivery**: Reliable delivery queue with exponential backoff retry, dead letter queue (DLQ) notifications
- **S3 Attachment Storage**: Optional S3-compatible storage (AWS S3, MinIO, Ceph) with presigned URL support
- **Raw Message Preservation**: Optional complete-MIME archiving to S3, configurable per domain and per rule
- **Rule Engine**: Conditional routing based on email attributes (from, to, subject, headers, etc.)
- **REST API**: Full management API with OpenAPI documentation
- **Multi-tenant**: Domain-based isolation with role-based access control
- **Rate Limiting**: Configurable limits for both API and SMTP (per-IP connection/message limits)
- **Prometheus Metrics**: `/metrics` endpoint with SMTP, webhook, queue and auth metrics, with optional IP allowlisting
- **Security**: SSRF protection for webhook URLs, salted API key hashing, scoped API keys, optional encryption at rest for webhook headers
- **Queue Backpressure**: Configurable limits to prevent unbounded queue growth
- **Soft Delete**: Deleted users, API keys, domains and recipients are restorable; delivery history survives, permanent removal is a separate superuser step or an optional retention job
- **Automatic Cleanup**: Background worker for delivery-log and soft-delete retention
- **Horizontal Scaling**: Stateless design with database-backed task distribution

## Packages

| Package | Install | What it is |
|---|---|---|
| [`fastsmtp`](https://pypi.org/project/fastsmtp/) | `pip install fastsmtp` | The server, and the `fastsmtp` admin CLI |
| [`fastsmtp-cli`](https://pypi.org/project/fastsmtp-cli/) | `pip install fastsmtp-cli` | `fsmtp`, the remote CLI. Talks to a server over HTTP and shares none of its dependencies |

Container images are published to
[ghcr.io/jsenecal/fastsmtp](https://github.com/jsenecal/fastsmtp/pkgs/container/fastsmtp).

## Quick Start

Requires Python 3.12+ and PostgreSQL 16+ (or MariaDB 10.6+).

```bash
pip install fastsmtp

export FASTSMTP_DATABASE_URL="postgresql+asyncpg://user:pass@localhost/fastsmtp"
export FASTSMTP_ROOT_API_KEY="your-secure-root-key"

fastsmtp db upgrade head   # apply migrations first, every time
fastsmtp serve
```

Migrations are never applied automatically, and the server refuses to start against a
database behind its own build. Run `fastsmtp db upgrade head` before starting a newer
version; it needs `FASTSMTP_DATABASE_URL` and nothing else.

For Docker, Docker Compose and a MinIO-backed stack, see
[Getting Started](https://jsenecal.github.io/fastsmtp/getting-started/).

## Documentation

| Page | Covers |
|---|---|
| [Getting Started](https://jsenecal.github.io/fastsmtp/getting-started/) | Install from PyPI, source or Docker, and Compose stacks |
| [Configuration](https://jsenecal.github.io/fastsmtp/configuration/) | Every `FASTSMTP_*` environment variable |
| [Rule Engine](https://jsenecal.github.io/fastsmtp/rules/) | Fields, operators, actions, RE2 patterns |
| [Webhook Payload](https://jsenecal.github.io/fastsmtp/webhooks/) | What your endpoint receives, and delivery statuses |
| [API Reference](https://jsenecal.github.io/fastsmtp/api/) | Routes, key scopes, deletion and restore semantics |
| [Monitoring](https://jsenecal.github.io/fastsmtp/monitoring/) | Prometheus metrics, health checks, scrape access |
| [Server CLI](https://jsenecal.github.io/fastsmtp/cli/fastsmtp/) | `fastsmtp serve`, `db`, `user`, `domain`, maintenance |
| [Remote CLI](https://jsenecal.github.io/fastsmtp/cli/fsmtp/) | `fsmtp` command reference |
| [Development](https://jsenecal.github.io/fastsmtp/development/) | Test suite, migration tests, docs site |
| [Releasing](https://jsenecal.github.io/fastsmtp/releasing/) | Version bumps, labels, publishing |

A running server also serves its own OpenAPI documentation at `/docs` and `/redoc`.

## Development

```bash
uv sync --all-packages --dev
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

See [Development](https://jsenecal.github.io/fastsmtp/development/) for the migration
tests and for working on the documentation site.

## License

AGPL-3.0-or-later - this program is free software: you can redistribute it and/or
modify it under the terms of the GNU Affero General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your option) any later
version. See the [LICENSE](LICENSE) file for details.
