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
- `forward` - Forward to webhook; see [Webhook URL Override](#webhook-url-override)
- `drop` - Silently drop the email
- `quarantine` - Mark as quarantined

## Webhook URL Override

A rule may set `webhook_url_override` (`--webhook-url` on
`fsmtp rules rule create|update`) to send a matching message somewhere other than the
recipient's configured webhook:

```bash
fsmtp rules rule create <domain-id> <ruleset-id> \
  --field has_attachment \
  --operator equals \
  --value true \
  --action forward \
  --webhook-url https://n8n.example.com/webhook/mail-inspect
```

Clear it again by passing an empty string: `--webhook-url ''`.

### It replaces the destination, it does not add one

A message is delivered once per recipient, so the override redirects that delivery
rather than duplicating it. The recipient's own webhook receives nothing for a message
the override caught. A pipeline that inspects mail and then passes it on has to make
that second hop itself.

### Where it sits among the other rule outcomes

Every matching rule in a ruleset contributes, unless the ruleset sets `stop_on_match`.
Rulesets are evaluated by descending priority and rules within one in their stored
order, and the four outcomes combine differently:

| Outcome | How matches combine |
|---|---|
| `action` | Most severe wins: `drop` over `quarantine` over `forward` and `tag` |
| `webhook_url_override` | Last match wins - a later rule's override replaces an earlier one |
| `add_tags` | Union of every match, de-duplicated |
| `preserve_raw` | Any match setting it is enough |

Note the asymmetry: the action is decided by severity, but the override is decided by
position. Two matching rules with different overrides do not conflict, they queue, and
the later one silently wins.

An override on a message that ends up dropped has no effect, since a drop is honoured
before any delivery is queued. Raw preservation still happens, so a rule can archive a
message to S3 and drop it.

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
