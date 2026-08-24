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

## Domain Management

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

## Maintenance

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
