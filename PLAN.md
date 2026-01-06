# FastSMTP - SMTP-to-Webhook Relay Server

## Project Overview
Build a TLS-capable async SMTP server that receives emails, validates DKIM/SPF, and forwards contents to configurable webhooks (primarily n8n). Include a REST API for configuration, a server CLI for administration, and a standalone remote CLI client for API interaction. Designed for Kubernetes deployment with horizontal scaling.

## Tech Stack

### Server (`fastsmtp`)
- **Runtime**: Python 3.12+
- **Package Manager**: uv
- **Linting/Formatting**: ruff
- **SMTP**: aiosmtpd
- **API**: FastAPI + uvicorn
- **Config**: pydantic-settings
- **CLI**: typer
- **HTTP Client**: httpx (async)
- **Database**: PostgreSQL (asyncpg) or MariaDB (aiomysql) via SQLAlchemy async
- **Migrations**: alembic
- **Retry**: tenacity
- **Email Auth**: dkimpy (DKIM), pyspf + dnspython (SPF)

### Remote CLI (`fastsmtp-cli`)
- **Runtime**: Python 3.12+
- **CLI**: typer
- **HTTP Client**: httpx
- **Config**: pydantic-settings (for client config)
- **Output**: rich (tables, syntax highlighting)

## Repository Structure
```
fastsmtp/
├── pyproject.toml              # Workspace root
├── packages/
│   ├── fastsmtp/               # Server package
│   │   ├── pyproject.toml
│   │   ├── alembic.ini
│   │   ├── alembic/
│   │   │   ├── env.py
│   │   │   ├── script.py.mako
│   │   │   └── versions/
│   │   └── src/
│   │       └── fastsmtp/
│   │           ├── __init__.py
│   │           ├── main.py
│   │           ├── cli.py              # Server admin CLI
│   │           ├── config.py
│   │           ├── db/
│   │           │   ├── __init__.py
│   │           │   ├── session.py
│   │           │   └── models.py
│   │           ├── schemas/            # Shared schemas (also used by CLI)
│   │           │   ├── __init__.py
│   │           │   ├── domain.py
│   │           │   ├── recipient.py
│   │           │   ├── rule.py
│   │           │   ├── user.py
│   │           │   └── webhook.py
│   │           ├── smtp/
│   │           │   ├── __init__.py
│   │           │   ├── server.py
│   │           │   ├── tls.py
│   │           │   └── validation.py
│   │           ├── webhook/
│   │           │   ├── __init__.py
│   │           │   ├── dispatcher.py
│   │           │   └── queue.py
│   │           ├── rules/
│   │           │   ├── __init__.py
│   │           │   ├── engine.py
│   │           │   └── conditions.py
│   │           ├── auth/
│   │           │   ├── __init__.py
│   │           │   ├── keys.py
│   │           │   └── dependencies.py
│   │           └── api/
│   │               ├── __init__.py
│   │               ├── router.py
│   │               ├── domains.py
│   │               ├── recipients.py
│   │               ├── rules.py
│   │               ├── users.py
│   │               └── operations.py
│   │
│   └── fastsmtp-cli/           # Remote CLI package
│       ├── pyproject.toml
│       └── src/
│           └── fastsmtp_cli/
│               ├── __init__.py
│               ├── main.py             # Typer app entry
│               ├── config.py           # Client configuration
│               ├── client.py           # API client wrapper
│               ├── output.py           # Rich formatting helpers
│               └── commands/
│                   ├── __init__.py
│                   ├── auth.py         # Login, key management
│                   ├── domains.py
│                   ├── recipients.py
│                   ├── rules.py
│                   ├── users.py        # Superuser commands
│                   └── ops.py          # Test, logs, health
```

## Server Package (`fastsmtp`)

### Configuration (pydantic-settings)
```python
class Settings(BaseSettings):
    # SMTP
    smtp_host: str = "0.0.0.0"
    smtp_port: int = 2525
    smtp_tls_port: int = 4650
    smtp_tls_cert: Path | None = None
    smtp_tls_key: Path | None = None
    smtp_require_starttls: bool = False
    
    # Email authentication
    smtp_verify_dkim: bool = True
    smtp_verify_spf: bool = True
    smtp_reject_dkim_fail: bool = False
    smtp_reject_spf_fail: bool = False
    
    # API
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    
    # Database
    database_url: str  # postgresql+asyncpg://... or mysql+aiomysql://...
    database_pool_size: int = 5
    database_pool_max_overflow: int = 10
    
    # Webhook defaults
    webhook_timeout: int = 30
    webhook_max_retries: int = 5
    webhook_retry_base_delay: float = 1.0
    
    # Security
    root_api_key: SecretStr
    api_key_hash_algorithm: str = "sha256"
    
    # K8s/Operations
    instance_id: str = Field(default_factory=lambda: os.getenv("HOSTNAME", uuid4().hex[:8]))
    
    model_config = SettingsConfigDict(
        env_prefix="FASTSMTP_",
        env_file=".env",
    )
```

### Database Models
```python
# All models include: id (UUID), created_at, updated_at

class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID]
    username: Mapped[str]  # unique
    email: Mapped[str | None]
    is_active: Mapped[bool] = True
    is_superuser: Mapped[bool] = False
    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="user")
    domain_memberships: Mapped[list["DomainMember"]] = relationship(back_populates="user")

class APIKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[uuid.UUID]
    user_id: Mapped[uuid.UUID] = ForeignKey("users.id", ondelete="CASCADE")
    key_hash: Mapped[str]
    key_prefix: Mapped[str]  # fsmtp_xxxxxxxx
    name: Mapped[str]
    scopes: Mapped[list[str]]  # JSON
    expires_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    is_active: Mapped[bool] = True
    user: Mapped["User"] = relationship(back_populates="api_keys")

class Domain(Base):
    __tablename__ = "domains"
    id: Mapped[uuid.UUID]
    domain_name: Mapped[str]  # unique
    is_enabled: Mapped[bool] = True
    verify_dkim: Mapped[bool | None] = None
    verify_spf: Mapped[bool | None] = None
    reject_dkim_fail: Mapped[bool | None] = None
    reject_spf_fail: Mapped[bool | None] = None
    members: Mapped[list["DomainMember"]] = relationship(back_populates="domain")
    recipients: Mapped[list["Recipient"]] = relationship(back_populates="domain")
    rulesets: Mapped[list["RuleSet"]] = relationship(back_populates="domain")

class DomainMember(Base):
    __tablename__ = "domain_members"
    id: Mapped[uuid.UUID]
    user_id: Mapped[uuid.UUID] = ForeignKey("users.id", ondelete="CASCADE")
    domain_id: Mapped[uuid.UUID] = ForeignKey("domains.id", ondelete="CASCADE")
    role: Mapped[str] = "member"  # owner, admin, member
    user: Mapped["User"] = relationship(back_populates="domain_memberships")
    domain: Mapped["Domain"] = relationship(back_populates="members")
    __table_args__ = (UniqueConstraint("user_id", "domain_id"),)

class Recipient(Base):
    __tablename__ = "recipients"
    id: Mapped[uuid.UUID]
    domain_id: Mapped[uuid.UUID] = ForeignKey("domains.id", ondelete="CASCADE")
    local_part: Mapped[str | None]  # NULL = catch-all
    webhook_url: Mapped[str]
    webhook_headers: Mapped[dict]  # JSON
    is_enabled: Mapped[bool] = True
    domain: Mapped["Domain"] = relationship(back_populates="recipients")
    __table_args__ = (UniqueConstraint("domain_id", "local_part"),)

class RuleSet(Base):
    __tablename__ = "rulesets"
    id: Mapped[uuid.UUID]
    domain_id: Mapped[uuid.UUID] = ForeignKey("domains.id", ondelete="CASCADE")
    name: Mapped[str]
    priority: Mapped[int] = 0
    stop_on_match: Mapped[bool] = True
    is_enabled: Mapped[bool] = True
    domain: Mapped["Domain"] = relationship(back_populates="rulesets")
    rules: Mapped[list["Rule"]] = relationship(order_by="Rule.order", back_populates="ruleset")
    __table_args__ = (UniqueConstraint("domain_id", "name"),)

class Rule(Base):
    __tablename__ = "rules"
    id: Mapped[uuid.UUID]
    ruleset_id: Mapped[uuid.UUID] = ForeignKey("rulesets.id", ondelete="CASCADE")
    order: Mapped[int]
    field: Mapped[str]  # from, to, subject, header:X-Custom, body, has_attachment, dkim_result, spf_result, etc.
    operator: Mapped[str]  # equals, contains, regex, starts_with, ends_with, exists
    value: Mapped[str]
    case_sensitive: Mapped[bool] = False
    action: Mapped[str] = "forward"  # forward, drop, tag, quarantine
    webhook_url_override: Mapped[str | None]
    add_tags: Mapped[list[str]]  # JSON
    ruleset: Mapped["RuleSet"] = relationship(back_populates="rules")

class DeliveryLog(Base):
    __tablename__ = "delivery_log"
    id: Mapped[uuid.UUID]
    domain_id: Mapped[uuid.UUID] = ForeignKey("domains.id", ondelete="SET NULL")
    message_id: Mapped[str]
    recipient_id: Mapped[uuid.UUID | None] = ForeignKey("recipients.id", ondelete="SET NULL")
    webhook_url: Mapped[str]
    payload_hash: Mapped[str]
    status: Mapped[str]  # pending, delivered, failed, exhausted
    attempts: Mapped[int] = 0
    next_retry_at: Mapped[datetime | None]
    last_error: Mapped[str | None]
    last_status_code: Mapped[int | None]
    instance_id: Mapped[str]
    delivered_at: Mapped[datetime | None]
    payload: Mapped[dict]  # JSON
    dkim_result: Mapped[str | None]
    spf_result: Mapped[str | None]
```

### DKIM/SPF Validation
```python
# smtp/validation.py
@dataclass
class EmailAuthResult:
    dkim_result: str  # pass, fail, none, temperror, permerror
    dkim_domain: str | None
    dkim_selector: str | None
    spf_result: str  # pass, fail, softfail, neutral, none, temperror, permerror
    spf_domain: str | None
    client_ip: str

async def verify_dkim(message: bytes) -> tuple[str, str | None, str | None]:
    """Verify DKIM signature (run in executor)"""
    ...

async def verify_spf(client_ip: str, mail_from: str, helo: str) -> tuple[str, str | None]:
    """Verify SPF record"""
    ...

async def validate_email_auth(
    message: bytes, client_ip: str, mail_from: str, helo: str
) -> EmailAuthResult:
    """Run DKIM and SPF validation in parallel"""
    ...
```

### Auth System

**Domain Roles**: `owner`, `admin`, `member`

**Scopes**:
- `domains:read`, `domains:write`, `domains:delete`
- `members:read`, `members:write`
- `recipients:read`, `recipients:write`
- `rules:read`, `rules:write`
- `logs:read`
- `users:read`, `users:write` (superuser)
- `admin` (all)

### API Endpoints
```
# Auth
POST   /api/v1/auth/keys
GET    /api/v1/auth/keys
DELETE /api/v1/auth/keys/{key_id}
POST   /api/v1/auth/keys/{key_id}/rotate
GET    /api/v1/auth/me

# Users (superuser)
GET/POST       /api/v1/users
GET/PUT/DELETE /api/v1/users/{user_id}

# Domains
GET            /api/v1/domains
POST           /api/v1/domains                              # superuser
GET/PUT        /api/v1/domains/{domain_id}
DELETE         /api/v1/domains/{domain_id}                  # owner/superuser

# Domain members
GET            /api/v1/domains/{domain_id}/members
POST           /api/v1/domains/{domain_id}/members
PUT            /api/v1/domains/{domain_id}/members/{user_id}
DELETE         /api/v1/domains/{domain_id}/members/{user_id}

# Recipients
GET/POST       /api/v1/domains/{domain_id}/recipients
GET/PUT/DELETE /api/v1/domains/{domain_id}/recipients/{recipient_id}

# RuleSets
GET/POST       /api/v1/domains/{domain_id}/rulesets
GET/PUT/DELETE /api/v1/domains/{domain_id}/rulesets/{ruleset_id}
POST           /api/v1/domains/{domain_id}/rulesets/{ruleset_id}/rules
PUT/DELETE     /api/v1/domains/{domain_id}/rules/{rule_id}
POST           /api/v1/domains/{domain_id}/rulesets/{ruleset_id}/reorder

# Operations
POST           /api/v1/test-webhook
GET            /api/v1/domains/{domain_id}/delivery-log
POST           /api/v1/delivery-log/{id}/retry
GET            /api/v1/health
GET            /api/v1/ready
```

### Server CLI (`fastsmtp`)

Direct DB access for bootstrapping and administration:
```bash
# Server
fastsmtp serve [--smtp-only|--api-only|--worker-only]

# Database
fastsmtp db upgrade
fastsmtp db revision -m "description"
fastsmtp db current
fastsmtp db downgrade <revision>

# Bootstrap
fastsmtp init                                    # Interactive setup wizard

# User management (direct DB)
fastsmtp user create <username> [--superuser] [--email EMAIL]
fastsmtp user list
fastsmtp user delete <username>
fastsmtp user set-superuser <username> --enable|--disable
fastsmtp user generate-key <username> [--name NAME] [--scopes SCOPE,...]

# Domain bootstrap (direct DB, superuser operations)
fastsmtp domain create <domain_name>
fastsmtp domain list
fastsmtp domain delete <domain_name>
fastsmtp domain add-member <domain> <username> [--role owner|admin|member]
fastsmtp domain remove-member <domain> <username>

# Debug/Test
fastsmtp test-dkim <message_file>
fastsmtp test-spf <ip> <mail_from>
fastsmtp show-config
```

---

## Remote CLI Package (`fastsmtp-cli`)

Lightweight API client for day-to-day operations.

### Client Configuration
```python
# config.py
class ClientConfig(BaseSettings):
    api_url: str = "http://localhost:8000"
    api_key: SecretStr | None = None
    default_domain: str | None = None  # convenience for single-domain users
    output_format: str = "table"  # table, json, yaml
    
    model_config = SettingsConfigDict(
        env_prefix="FASTSMTP_",
        env_file=".env",
    )

class ConfigFile(BaseModel):
    """~/.config/fastsmtp/config.toml or ~/.fastsmtp.toml"""
    profiles: dict[str, Profile] = {}
    default_profile: str = "default"

class Profile(BaseModel):
    api_url: str
    api_key: str | None = None
    default_domain: str | None = None
```

### API Client Wrapper
```python
# client.py
class FastSMTPClient:
    def __init__(self, config: ClientConfig):
        self.config = config
        self._client = httpx.Client(
            base_url=config.api_url,
            headers={"X-API-Key": config.api_key.get_secret_value()} if config.api_key else {},
            timeout=30.0,
        )
    
    def __enter__(self) -> Self:
        return self
    
    def __exit__(self, *args):
        self._client.close()
    
    # Auth
    def whoami(self) -> UserResponse: ...
    def list_keys(self) -> list[APIKeyResponse]: ...
    def create_key(self, name: str, scopes: list[str] | None = None) -> APIKeyCreateResponse: ...
    def delete_key(self, key_id: str) -> None: ...
    def rotate_key(self, key_id: str) -> APIKeyCreateResponse: ...
    
    # Domains
    def list_domains(self) -> list[DomainResponse]: ...
    def get_domain(self, domain_id: str) -> DomainResponse: ...
    def create_domain(self, domain_name: str, **kwargs) -> DomainResponse: ...
    def update_domain(self, domain_id: str, **kwargs) -> DomainResponse: ...
    def delete_domain(self, domain_id: str) -> None: ...
    
    # Members
    def list_members(self, domain_id: str) -> list[MemberResponse]: ...
    def add_member(self, domain_id: str, user_id: str, role: str) -> MemberResponse: ...
    def update_member(self, domain_id: str, user_id: str, role: str) -> MemberResponse: ...
    def remove_member(self, domain_id: str, user_id: str) -> None: ...
    
    # Recipients
    def list_recipients(self, domain_id: str) -> list[RecipientResponse]: ...
    def create_recipient(self, domain_id: str, local_part: str | None, webhook_url: str, **kwargs) -> RecipientResponse: ...
    def update_recipient(self, domain_id: str, recipient_id: str, **kwargs) -> RecipientResponse: ...
    def delete_recipient(self, domain_id: str, recipient_id: str) -> None: ...
    
    # RuleSets & Rules
    def list_rulesets(self, domain_id: str) -> list[RuleSetResponse]: ...
    def create_ruleset(self, domain_id: str, name: str, **kwargs) -> RuleSetResponse: ...
    def update_ruleset(self, domain_id: str, ruleset_id: str, **kwargs) -> RuleSetResponse: ...
    def delete_ruleset(self, domain_id: str, ruleset_id: str) -> None: ...
    def add_rule(self, domain_id: str, ruleset_id: str, **kwargs) -> RuleResponse: ...
    def update_rule(self, domain_id: str, rule_id: str, **kwargs) -> RuleResponse: ...
    def delete_rule(self, domain_id: str, rule_id: str) -> None: ...
    def reorder_rules(self, domain_id: str, ruleset_id: str, rule_ids: list[str]) -> None: ...
    
    # Operations
    def test_webhook(self, webhook_url: str, **kwargs) -> TestWebhookResponse: ...
    def get_delivery_log(self, domain_id: str, **filters) -> list[DeliveryLogResponse]: ...
    def retry_delivery(self, log_id: str) -> DeliveryLogResponse: ...
    def health(self) -> HealthResponse: ...
```

### Output Formatting
```python
# output.py
from rich.console import Console
from rich.table import Table

console = Console()

def print_domains(domains: list[DomainResponse], format: str = "table"):
    if format == "json":
        console.print_json(data=[d.model_dump() for d in domains])
        return
    
    table = Table(title="Domains")
    table.add_column("ID", style="dim")
    table.add_column("Domain")
    table.add_column("Enabled")
    table.add_column("DKIM")
    table.add_column("SPF")
    
    for d in domains:
        table.add_row(
            str(d.id)[:8],
            d.domain_name,
            "✓" if d.is_enabled else "✗",
            d.verify_dkim or "default",
            d.verify_spf or "default",
        )
    
    console.print(table)

# Similar helpers for recipients, rules, logs, etc.
```

### Remote CLI Commands (`fsmtp`)
```bash
# Configuration
fsmtp config init                               # Interactive config setup
fsmtp config show
fsmtp config set <key> <value>
fsmtp config profiles list
fsmtp config profiles add <name> --api-url URL --api-key KEY
fsmtp config profiles use <name>

# Auth
fsmtp auth whoami                               # Show current user info
fsmtp auth keys list
fsmtp auth keys create [--name NAME] [--scopes SCOPE,...]
fsmtp auth keys delete <key_id>
fsmtp auth keys rotate <key_id>

# Domains
fsmtp domains list
fsmtp domains show <domain>                     # by name or ID
fsmtp domains create <domain_name> [--verify-dkim] [--verify-spf] [--reject-dkim-fail] [--reject-spf-fail]  # superuser
fsmtp domains update <domain> [--enable|--disable] [--verify-dkim BOOL] ...
fsmtp domains delete <domain>

# Domain members
fsmtp members list <domain>
fsmtp members add <domain> <username> [--role owner|admin|member]
fsmtp members update <domain> <username> --role <role>
fsmtp members remove <domain> <username>

# Recipients
fsmtp recipients list <domain>
fsmtp recipients add <domain> <local_part> <webhook_url> [--headers KEY=VALUE]...
fsmtp recipients add <domain> "*" <webhook_url>    # catch-all shorthand
fsmtp recipients update <domain> <recipient_id> [--webhook-url URL] [--enable|--disable]
fsmtp recipients delete <domain> <recipient_id>

# RuleSets
fsmtp rulesets list <domain>
fsmtp rulesets create <domain> <name> [--priority N] [--stop-on-match|--no-stop-on-match]
fsmtp rulesets update <domain> <ruleset> [--priority N] [--enable|--disable]
fsmtp rulesets delete <domain> <ruleset>

# Rules
fsmtp rules list <domain> <ruleset>
fsmtp rules add <domain> <ruleset> \
    --field <field> \
    --op <operator> \
    --value <value> \
    [--action forward|drop|tag|quarantine] \
    [--webhook-override URL] \
    [--tag TAG]...
fsmtp rules update <domain> <rule_id> [--field ...] [--action ...]
fsmtp rules delete <domain> <rule_id>
fsmtp rules reorder <domain> <ruleset> <rule_id>...   # reorder by listing IDs in order

# Operations
fsmtp test webhook <url> [--subject SUBJECT] [--from FROM] [--body BODY]
fsmtp logs list <domain> [--status pending|delivered|failed|exhausted] [--since DATETIME] [--limit N]
fsmtp logs show <log_id>
fsmtp logs retry <log_id>
fsmtp health                                    # Check server health

# Output control (global options)
fsmtp --format json domains list                # JSON output
fsmtp --format yaml domains list                # YAML output
fsmtp -o json domains list                      # Short form
```

### CLI Examples
```bash
# Initial setup
$ fsmtp config init
API URL [http://localhost:8000]: https://smtp.example.com
API Key: fsmtp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
Default domain (optional): example.com
Configuration saved to ~/.config/fastsmtp/config.toml

# Check connection
$ fsmtp auth whoami
User: jonathan
Email: jonathan@example.com
Superuser: Yes
Domains: example.com (owner), test.com (admin)

# List domains with JSON output
$ fsmtp -o json domains list
[{"id": "abc123", "domain_name": "example.com", ...}]

# Add a recipient
$ fsmtp recipients add example.com support https://n8n.example.com/webhook/support \
    --headers "Authorization=Bearer secret123"
✓ Created recipient support@example.com → https://n8n.example.com/webhook/support

# Add catch-all
$ fsmtp recipients add example.com "*" https://n8n.example.com/webhook/catchall
✓ Created catch-all recipient *@example.com → https://n8n.example.com/webhook/catchall

# Create a ruleset for spam filtering
$ fsmtp rulesets create example.com spam-filter --priority 10
✓ Created ruleset 'spam-filter' (id: xyz789)

# Add rules
$ fsmtp rules add example.com spam-filter \
    --field spf_result --op equals --value fail --action drop
✓ Added rule: DROP when spf_result equals 'fail'

$ fsmtp rules add example.com spam-filter \
    --field dkim_result --op equals --value fail --action tag --tag dkim-failed
✓ Added rule: TAG [dkim-failed] when dkim_result equals 'fail'

# Check delivery logs
$ fsmtp logs list example.com --status failed --since "1 hour ago"
┏━━━━━━━━┳━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ ID     ┃ Message ID        ┃ Status  ┃ Attempts ┃ Last Error  ┃
┡━━━━━━━━╇━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ abc123 │ <msg1@example.com>│ failed  │ 3        │ Timeout     │
│ def456 │ <msg2@example.com>│ failed  │ 2        │ 502 Bad GW  │
└────────┴───────────────────┴─────────┴──────────┴─────────────┘

# Retry failed delivery
$ fsmtp logs retry abc123
✓ Delivery abc123 queued for retry
```

---

## Package Configurations

### Root `pyproject.toml` (uv workspace)
```toml
[project]
name = "fastsmtp-workspace"
version = "0.1.0"
requires-python = ">=3.12"

[tool.uv.workspace]
members = ["packages/*"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "SIM", "ASYNC"]
```

### Server `packages/fastsmtp/pyproject.toml`
```toml
[project]
name = "fastsmtp"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.32",
    "pydantic-settings>=2.6",
    "typer>=0.14",
    "httpx>=0.28",
    "aiosmtpd>=1.4",
    "sqlalchemy[asyncio]>=2.0",
    "alembic>=1.14",
    "tenacity>=9.0",
    "dkimpy>=1.1",
    "pyspf>=2.0",
    "dnspython>=2.7",
]

[project.optional-dependencies]
postgres = ["asyncpg>=0.30"]
mariadb = ["aiomysql>=0.2"]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.24",
    "aiosmtplib>=3.0",
    "ruff>=0.8",
    "coverage>=7.0",
]

[project.scripts]
fastsmtp = "fastsmtp.cli:app"
```

### CLI `packages/fastsmtp-cli/pyproject.toml`
```toml
[project]
name = "fastsmtp-cli"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "typer>=0.14",
    "httpx>=0.28",
    "pydantic>=2.9",
    "pydantic-settings>=2.6",
    "rich>=13.9",
    "tomli>=2.0; python_version < '3.11'",
    "tomli-w>=1.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "respx>=0.21",  # httpx mocking
    "ruff>=0.8",
]

[project.scripts]
fsmtp = "fastsmtp_cli.main:app"
```

---

## Implementation Order

### Phase 1: Foundation
1. Workspace setup: uv, pyproject.toml files, ruff config
2. Server: Settings + async DB session factory
3. Server: Alembic + base models (User, APIKey, Domain, DomainMember)
4. Server: Auth dependencies
5. Server: FastAPI skeleton + health endpoints

### Phase 2: Core Server
6. Server: Domain/Member CRUD endpoints
7. Server: Recipient model + endpoints
8. Server: RuleSet/Rule models + endpoints
9. Server: DKIM/SPF validation module
10. Server: Basic SMTP server with auth validation
11. Server: Webhook queue + dispatcher
12. Server: Rules engine
13. Server: DeliveryLog + operations endpoints
14. Server: Server CLI (db, user, domain commands)
15. Server: TLS support

### Phase 3: Remote CLI
16. CLI: Config management (profiles, env)
17. CLI: API client wrapper
18. CLI: Output formatters (rich tables)
19. CLI: Auth commands
20. CLI: Domain/member commands
21. CLI: Recipient commands
22. CLI: Ruleset/rule commands
23. CLI: Operations commands (logs, test, health)

### Phase 4: Polish
24. Tests for both packages
25. Documentation
26. Dockerfile/compose/k8s manifests examples

