# Rule Engine

The rule engine allows conditional processing of emails based on various attributes. Rules are grouped into rulesets per domain and evaluated when an email is received, before it is queued for webhook delivery.

## Rule Fields

- `from`, `to`, `cc`, `subject`, `body`
- `header:<name>` (e.g., `header:X-Priority`)
- `has_attachments`, `attachment_count`
- `dkim_result`, `spf_result`

## Rule Operators

- `equals`, `not_equals`
- `contains`, `not_contains`
- `starts_with`, `ends_with`
- `matches` (regex)
- `greater_than`, `less_than` (for numeric fields)

## Rule Actions

- `tag` - Add a tag to the email
- `forward` - Forward to webhook (can override URL)
- `drop` - Silently drop the email
- `quarantine` - Mark as quarantined

## Example

Create a ruleset and a rule that tags spam using the [remote CLI](cli/fsmtp.md):

```bash
# Create a ruleset
fsmtp rules create example.com "Spam Filter" --priority 10

# Create a rule within the ruleset
fsmtp rules rule create example.com <ruleset-id> \
  --field subject \
  --operator contains \
  --value "[SPAM]" \
  --action tag \
  --action-value spam
```

Rules can also be managed through the [REST API](api.md).
