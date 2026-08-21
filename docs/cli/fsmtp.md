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

# Create a new API key
fsmtp auth create-key --name "CI/CD"

# Rotate an API key
fsmtp auth rotate-key <key-id>

# Delete an API key
fsmtp auth delete-key <key-id>
```

## Domain Management

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

## Recipient Management

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

## Rule Management

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

## Operations

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
