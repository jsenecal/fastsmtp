# Remote CLI (`fsmtp`)

The remote CLI connects to a FastSMTP server over HTTPS for remote management. For running the server itself, see the [server CLI](fastsmtp.md).

!!! note "Update conventions"

    Every `update` command sends only the options you name, so an omitted option
    leaves that setting untouched. Options backed by a *nullable* column go one
    further: passing an empty string (`--option ''`) clears the stored value —
    the CLI sends an explicit JSON null. This applies to `users update --email`,
    `recipient update --local` and `rules rule update --webhook-url`. Nullable
    boolean flags use `true`/`false`/`inherit` instead — see
    [Domain Management](#domain-management).

!!! note "Deletes are recoverable"

    `users delete`, `domain delete` and `recipient delete` are **soft**: the entry
    disappears from every list and lookup but can be brought back with the matching
    `restore` command, which the CLI names after each delete
    (`Restore with: fsmtp domain restore <id>`). `--include-deleted` shows deleted
    entries in `list`, `get`, `auth keys` and `ops log list`, with a red `Deleted`
    column or row. `delete --purge` is the permanent removal: superuser only, it works
    only on an entry that is already deleted, asks its own confirmation
    (`Permanently delete domain X? This cannot be undone.`) and reports `Domain X
    purged`. Run it on a live entry and the server answers
    `409 Domain must be deleted before it can be purged`. API keys are the
    exception: `auth delete-key` cannot be undone. See
    [Deletion, restore and purge](../api.md#deletion-restore-and-purge) for what each
    delete cascades to.

## Configuration

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

## Authentication

```bash
# Show current user info
fsmtp auth whoami

# List your API keys
fsmtp auth keys

# Include deleted keys, and keys retired before v0.5.0
fsmtp auth keys --include-deleted

# Create a new API key (optionally expiring after N days)
fsmtp auth create-key "CI/CD" --expires 90

# Rotate an API key (the old key is deleted)
fsmtp auth rotate-key <key-id>

# Delete an API key. Deleted keys cannot be restored; create or rotate instead
fsmtp auth delete-key <key-id>
```

## User Management

Every command in this group requires a superuser API key. Accounts have no password —
they authenticate with API keys — so no command here takes one.

```bash
# List all users
fsmtp users list

# Include deleted (restorable) users
fsmtp users list --include-deleted

# Get user details (a deleted user is 404 without --include-deleted)
fsmtp users get <user-id>
fsmtp users get <user-id> --include-deleted

# Create a user (only the username is required)
fsmtp users create alice --email alice@example.com

# Create a superuser
fsmtp users create alice --email alice@example.com --superuser

# Rename a user or change their email
fsmtp users update <user-id> --username bob --email bob@example.com

# Clear a user's email (nullable column: '' sends an explicit null)
fsmtp users update <user-id> --email ''

# Deactivate an account, or grant/revoke superuser
fsmtp users update <user-id> --inactive
fsmtp users update <user-id> --superuser
fsmtp users update <user-id> --no-superuser

# Delete a user (prompts; --force skips the prompt). Soft: the user's API keys
# are revoked for good, memberships come back on restore
fsmtp users delete <user-id>

# Restore a deleted user. Keys revoked at deletion are not restored; create new ones
fsmtp users restore <user-id>

# Permanently remove an already-deleted user with their keys and memberships (superuser)
fsmtp users delete <user-id> --purge
```

!!! note "Options left off are left alone"

    `users update` sends only the options you name, so an omitted flag leaves that
    column untouched, while `--email ''` clears the stored address. At least one
    option is required.

## Domain Management

Domains carry three-valued flags: `true` and `false` pin the setting for the domain,
`inherit` clears it so the domain follows the server-wide default, and leaving the option
off entirely leaves the setting untouched.

```bash
# List domains you have access to
fsmtp domain list

# Include deleted domains (all of them for a superuser, those you own otherwise)
fsmtp domain list --include-deleted

# Get domain details (a deleted domain is 404 without --include-deleted; owner only)
fsmtp domain get <domain-id>
fsmtp domain get <domain-id> --include-deleted

# Create a new domain
fsmtp domain create example.com

# Create a domain that archives every raw message to S3
fsmtp domain create example.com --preserve-raw-message true

# Update domain settings
fsmtp domain update <domain-id> --disabled
fsmtp domain update <domain-id> --verify-dkim true --reject-dkim-fail false

# Stop overriding the server-wide raw-preservation default
fsmtp domain update <domain-id> --preserve-raw-message inherit

# Delete a domain (owner). Soft: its recipients are deleted with it and their
# queued deliveries cancelled; rulesets and members come back on restore
fsmtp domain delete <domain-id>

# Restore a deleted domain and the recipients deleted with it (owner)
fsmtp domain restore <domain-id>

# Permanently remove an already-deleted domain with its recipients, rulesets and
# members (superuser). Delivery history is kept with its domain link cleared
fsmtp domain delete <domain-id> --purge

# Manage domain members
fsmtp domain member list <domain-id>
fsmtp domain member add <domain-id> <user-id> --role admin
fsmtp domain member update <domain-id> <user-id> --role member
fsmtp domain member remove <domain-id> <user-id>
```

!!! note "Raw preservation needs S3"

    `--preserve-raw-message true` is rejected with a 422 when the server has no S3
    storage configured; the CLI prints the missing settings. See
    [Raw Message Preservation](../configuration.md#raw-message-preservation-s3).

## Recipient Management

Recipients live under a domain, so every command takes the domain ID first.

```bash
# List recipients for a domain
fsmtp recipient list <domain-id>

# Include deleted recipients (admin). Works on a deleted domain too, for its owners
fsmtp recipient list <domain-id> --include-deleted

# Get recipient details (a deleted recipient is 404 without --include-deleted)
fsmtp recipient get <domain-id> <recipient-id>
fsmtp recipient get <domain-id> <recipient-id> --include-deleted

# Create a recipient with webhook (omit --local for a catch-all)
fsmtp recipient create <domain-id> https://n8n.example.com/webhook/email --local support

# Send extra headers with the webhook request
fsmtp recipient create <domain-id> https://n8n.example.com/webhook/email \
  --local support \
  --header "X-Token=secret"

# Update recipient
fsmtp recipient update <domain-id> <recipient-id> \
  --webhook https://new-webhook.example.com/email

# Clear the local part to turn a recipient into the domain's catch-all
fsmtp recipient update <domain-id> <recipient-id> --local ''

# Delete recipient. Soft: its pending and failed deliveries are cancelled
fsmtp recipient delete <domain-id> <recipient-id>

# Restore a deleted recipient (the domain must be live; restore it first otherwise)
fsmtp recipient restore <domain-id> <recipient-id>

# Permanently remove an already-deleted recipient (superuser). Its delivery
# history is kept with the recipient link cleared
fsmtp recipient delete <domain-id> <recipient-id> --purge
```

## Rule Management

Rulesets and rules are nested under a domain too. Rules have no name and no per-rule
priority: they are evaluated in the ruleset's own order, which `rule reorder` sets.

```bash
# List rulesets for a domain
fsmtp rules list <domain-id>

# Get ruleset with all rules
fsmtp rules get <domain-id> <ruleset-id>

# Create a ruleset
fsmtp rules create <domain-id> "Spam Filter" --priority 10

# Update ruleset
fsmtp rules update <domain-id> <ruleset-id> --priority 20 --no-stop-on-match

# Delete ruleset
fsmtp rules delete <domain-id> <ruleset-id>

# List the rules in a ruleset
fsmtp rules rule list <domain-id> <ruleset-id>

# Show one rule
fsmtp rules rule get <domain-id> <ruleset-id> <rule-id>

# Create a rule within a ruleset (appended at the end)
fsmtp rules rule create <domain-id> <ruleset-id> \
  --field subject \
  --operator contains \
  --value "[SPAM]" \
  --action tag \
  --tag spam

# Archive the raw MIME message in S3 whenever the rule matches
fsmtp rules rule create <domain-id> <ruleset-id> \
  --field has_attachment \
  --operator exists \
  --value "" \
  --action forward \
  --preserve-raw

# Update a rule (rules are addressed by domain, not by ruleset)
fsmtp rules rule update <domain-id> <rule-id> --action drop
fsmtp rules rule update <domain-id> <rule-id> --no-preserve-raw

# Remove a rule's webhook override so it falls back to the recipient's URL
fsmtp rules rule update <domain-id> <rule-id> --webhook-url ''

# Set the evaluation order of a ruleset's rules
fsmtp rules rule reorder <domain-id> <ruleset-id> <rule-id-1> <rule-id-2>

# Delete a rule
fsmtp rules rule delete <domain-id> <rule-id>
```

Valid fields are `from`, `to`, `subject`, `body`, `has_attachment`, `dkim_result`,
`spf_result`, or `header:X-Custom-Header`. Valid operators are `equals`, `contains`,
`regex`, `starts_with`, `ends_with` and `exists`. Valid actions are `forward`, `drop`,
`tag` and `quarantine`. `regex` patterns use
[RE2 syntax](https://github.com/google/re2/wiki/Syntax) (no backreferences or
lookaround); the server rejects patterns RE2 cannot compile.

## Operations

```bash
# Check server health
fsmtp ops health

# Check server readiness (includes DB)
fsmtp ops ready

# Test a webhook URL
fsmtp ops test-webhook https://webhook.site/xxx

# View delivery logs
fsmtp ops log list <domain-id>
fsmtp ops log list <domain-id> --status failed --limit 50

# Deliveries cancelled because their recipient or domain was deleted
fsmtp ops log list <domain-id> --status cancelled

# Read the history of a deleted domain (owner or superuser)
fsmtp ops log list <domain-id> --include-deleted

# Get delivery log details
fsmtp ops log get <log-id>

# Retry a failed, exhausted or cancelled delivery. A cancelled one is accepted
# only once its recipient and domain are live again (409 otherwise)
fsmtp ops log retry <log-id>
```

See [Delivery statuses](../webhooks.md#delivery-statuses) for the status vocabulary.
