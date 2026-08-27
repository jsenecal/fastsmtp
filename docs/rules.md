# Rule Engine

The rule engine allows conditional processing of emails based on various attributes. Rules are grouped into rulesets per domain and evaluated when an email is received, before it is queued for webhook delivery.

## Rule Fields

- `from`, `to`, `subject`, `body`
- `header:<name>` (e.g., `header:X-Priority`)
- `has_attachment` - inline images that the HTML body actually renders, such as
  signature logos, are delivered in the webhook payload but do not set this
  field. Everything else the message carries does, including a part that claims
  an inline disposition without being referenced from the body; see
  [Inline images and Content-ID](webhooks.md#inline-images-and-content-id)
- `dkim_result`, `spf_result` - a mechanism this rule's own domain does not verify
  reads as `none`, whatever another recipient's domain asked for; see
  [Per-domain overrides](configuration.md#per-domain-overrides)

## Rule Operators

- `equals`
- `contains`
- `starts_with`, `ends_with`
- `regex`
- `exists`

### Regex patterns use RE2 syntax

`regex` conditions are evaluated with [Google RE2](https://github.com/google/re2/wiki/Syntax),
which matches in linear time by construction, so an operator-supplied pattern can
never trigger catastrophic backtracking (ReDoS). The trade-off is that RE2 does not
support backreferences (`\1`) or lookaround (`(?=...)`, `(?!...)`, `(?<=...)`,
`(?<!...)`). The API rejects such patterns with a 422 when a rule is created or
updated; a pattern stored before this validation existed simply never matches and
logs a warning.

## Rule Actions

- `tag` - Add a tag to the email
- `forward` - Forward to webhook (can override URL)
- `drop` - Silently drop the email
- `quarantine` - Mark as quarantined

## Raw Message Preservation

Independent of the action, a rule may set `preserve_raw` (`--preserve-raw` on
`fsmtp rules rule create|update`) to archive the complete raw MIME message in S3 when it
matches. Because it is orthogonal to the action, a rule can archive
a message and still drop it. See
[Raw Message Preservation](configuration.md#raw-message-preservation-s3) for the storage
layout and the domain-level and global settings it combines with.

## Example

Create a ruleset and a rule that tags spam using the [remote CLI](cli/fsmtp.md):

```bash
# Create a ruleset
fsmtp rules create <domain-id> "Spam Filter" --priority 10

# Create a rule within the ruleset
fsmtp rules rule create <domain-id> <ruleset-id> \
  --field subject \
  --operator contains \
  --value "[SPAM]" \
  --action tag \
  --tag spam

# Archive the raw MIME message in S3 when the rule matches
fsmtp rules rule create <domain-id> <ruleset-id> \
  --field subject \
  --operator contains \
  --value "[SPAM]" \
  --action drop \
  --preserve-raw
```

Rules are appended to the end of the ruleset and evaluated in that order; use
`fsmtp rules rule reorder <domain-id> <ruleset-id> <rule-id>...` to change it.

Rules can also be managed through the [REST API](api.md).
