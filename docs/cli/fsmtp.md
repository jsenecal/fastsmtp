# Remote CLI (`fsmtp`)

The remote CLI connects to a FastSMTP server over HTTPS for remote management. For running the server itself, see the [server CLI](fastsmtp.md).

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

# Create a new API key (optionally expiring after N days)
fsmtp auth create-key "CI/CD" --expires 90

# Rotate an API key
fsmtp auth rotate-key <key-id>

# Delete an API key
fsmtp auth delete-key <key-id>
```

## Domain Management

Domains carry three-valued flags: `true` and `false` pin the setting for the domain,
`inherit` clears it so the domain follows the server-wide default, and leaving the option
off entirely leaves the setting untouched.

```bash
# List domains you have access to
fsmtp domain list

# Get domain details
fsmtp domain get <domain-id>

# Create a new domain
fsmtp domain create example.com

# Create a domain that archives every raw message to S3
fsmtp domain create example.com --preserve-raw-message true

# Update domain settings
fsmtp domain update <domain-id> --disabled
fsmtp domain update <domain-id> --verify-dkim true --reject-dkim-fail false

# Stop overriding the server-wide raw-preservation default
fsmtp domain update <domain-id> --preserve-raw-message inherit

# Delete a domain
fsmtp domain delete <domain-id>

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

# Get recipient details
fsmtp recipient get <domain-id> <recipient-id>

# Create a recipient with webhook (omit --local for a catch-all)
fsmtp recipient create <domain-id> https://n8n.example.com/webhook/email --local support

# Send extra headers with the webhook request
fsmtp recipient create <domain-id> https://n8n.example.com/webhook/email \
  --local support \
  --header "X-Token=secret"

# Update recipient
fsmtp recipient update <domain-id> <recipient-id> \
  --webhook https://new-webhook.example.com/email

# Delete recipient
fsmtp recipient delete <domain-id> <recipient-id>
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

# Set the evaluation order of a ruleset's rules
fsmtp rules rule reorder <domain-id> <ruleset-id> <rule-id-1> <rule-id-2>

# Delete a rule
fsmtp rules rule delete <domain-id> <rule-id>
```

Valid fields are `from`, `to`, `subject`, `body`, `has_attachment`, `dkim_result`,
`spf_result`, or `header:X-Custom-Header`. Valid operators are `equals`, `contains`,
`regex`, `starts_with`, `ends_with` and `exists`. Valid actions are `forward`, `drop`,
`tag` and `quarantine`.

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

# Get delivery log details
fsmtp ops log get <log-id>

# Retry a failed delivery
fsmtp ops log retry <log-id>
```
