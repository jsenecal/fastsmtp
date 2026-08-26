# Server CLI (`fastsmtp`)

FastSMTP provides two CLI tools:

- **`fastsmtp`** - Server-side CLI for running the server and administration (this page)
- **[`fsmtp`](fsmtp.md)** - Remote CLI client for managing FastSMTP from anywhere

The server CLI is used to run the FastSMTP server and perform local administration tasks.

## Starting the Server

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

## Database Management

The `db` commands read only `FASTSMTP_DATABASE_URL`. The root API key, S3 settings and
every other variable `fastsmtp serve` requires are not needed, so a one-off migration
Job or pod can be given just the database URL.

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

## User Management

Users and domains are addressed **by name**. Every command resolves the *live* entry of
that name; a deleted entry never gets in the way, so a name can be reused right after a
delete. The two commands that address deleted entries - `restore` and `delete --purge`  - 
take `--id <uuid>` when several deleted entries share the name (the command lists their
ids and refuses to guess). `--id` is refused on a plain `delete`, which always addresses
the live entry.

```bash
# Create a new user (only the username is required)
fastsmtp user create alice --email alice@example.com

# List all users
fastsmtp user list

# Include deleted (restorable) users, with a Deleted column
fastsmtp user list --include-deleted

# Grant or revoke superuser privileges
fastsmtp user set-superuser alice --enable
fastsmtp user set-superuser alice --disable

# Generate API key for user (refused for a deleted user). Without --scopes the key
# cannot reach the recipient, rule or delivery-log routes; see the scope table in
# the API reference
fastsmtp user generate-key alice --scopes admin
fastsmtp user generate-key alice --name ci --scopes recipients:read,logs:read

# Delete a user (prompts; -f skips the prompt). Soft: the user's API keys are
# revoked for good, memberships come back on restore
fastsmtp user delete alice

# Restore a deleted user. Keys revoked at deletion are not restored
fastsmtp user restore alice
fastsmtp user restore alice --id 3f1c...   # when several deleted users are named alice

# Permanently remove an already-deleted user with their keys and memberships.
# Refused on a live user: delete it first, then --purge
fastsmtp user delete alice --purge
fastsmtp user delete alice --purge --id 3f1c...
```

## Domain Management

```bash
# Create a domain
fastsmtp domain create example.com

# List all domains
fastsmtp domain list

# Include deleted (restorable) domains, with a Deleted column
fastsmtp domain list --include-deleted

# Add a member to domain (refused for a deleted user)
fastsmtp domain add-member example.com alice --role owner
fastsmtp domain add-member example.com bob --role admin
fastsmtp domain add-member example.com charlie --role member

# Remove member from domain (memberships have no soft delete; this is permanent).
# Unlike add-member this also reaches a deleted user, so a membership can be
# taken away without restoring the account first
fastsmtp domain remove-member example.com charlie

# Delete a domain (prompts; -f skips the prompt). Soft: its recipients are deleted
# with it and their queued deliveries cancelled; rulesets and members are kept
fastsmtp domain delete example.com

# Restore a deleted domain and the recipients deleted with it
fastsmtp domain restore example.com
fastsmtp domain restore example.com --id 9a2e...

# Permanently remove an already-deleted domain with its recipients, rulesets and
# members. Delivery history is kept with its domain link cleared
fastsmtp domain delete example.com --purge
```

Restoring a name that a live entry has since taken fails with
`Domain 'example.com' already exists; rename or purge it first`.

## Maintenance

```bash
# Clean up old delivery logs (respects retention settings)
fastsmtp cleanup

# Preview what would be deleted
fastsmtp cleanup --dry-run

# Override retention period
fastsmtp cleanup --older-than 30d

# Permanently remove users, API keys, domains and recipients deleted longer ago
# than FASTSMTP_SOFT_DELETE_RETENTION_DAYS
fastsmtp purge-deleted

# Preview: "Would purge 3 soft-deleted rows older than ... (recipients=1, ...)"
fastsmtp purge-deleted --dry-run

# Override the retention period (also the only way to run it when none is configured)
fastsmtp purge-deleted --older-than 30d

# Show current configuration
fastsmtp show-config

# Show version
fastsmtp version
```

`show-config` masks every credential it prints, `FASTSMTP_DATABASE_URL` included: the
row reads `**********`, not the connection string. Use it to confirm *which* settings a
shell resolves, not to read a password back out.

`generate-key` takes its scopes as one comma-separated string, where the remote CLI
repeats `--scope` instead. Both default to no scopes at all - see
[Key scopes](../api.md#key-scopes).

`purge-deleted` is the manual form of the retention job described in
[Retention](../configuration.md#retention). Without `FASTSMTP_SOFT_DELETE_RETENTION_DAYS`
and without `--older-than` it exits with
`No retention configured. Set FASTSMTP_SOFT_DELETE_RETENTION_DAYS or pass --older-than.`
`cleanup` stays delivery-log only.

### Converting webhook headers to encrypted storage

```bash
fastsmtp encrypt-existing
fastsmtp encrypt-existing --dry-run
fastsmtp encrypt-existing --batch-size 200
```

Backfills [webhook header encryption](../configuration.md#webhook-header-encryption)
onto recipients that already existed before a key was configured, and carries a key
rotation once the new key is in place. See that section for the required rollout and
rotation order.

- With no key configured it exits `1`, naming `FASTSMTP_ENCRYPTION_KEYS`.
- Default batch size 500, one transaction per batch.
- `--dry-run` reports what it would write and writes nothing.
- It re-encrypts **every** row on every run - it has no way to tell which key an
  existing envelope was written under without decrypting it first. Safe to repeat, but
  not a cheap no-op on a large table, and it bumps `updated_at` on every row it rewrites,
  so anything watching that column sees the whole table move.
- It converts soft-deleted recipients too: their headers are still in the database, and
  restoring one hands them back.
- If it hits a row that no configured key can decrypt, it stops, reports how many rows
  it got through, leaves the earlier batches committed, and exits `1`. It is safe to
  re-run once the missing key is back in `FASTSMTP_ENCRYPTION_KEYS`.
