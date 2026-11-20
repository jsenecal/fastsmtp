# Rule Engine

The rule engine allows conditional processing of emails based on various attributes. Rules are grouped into rulesets per domain and evaluated when an email is received, before it is queued for webhook delivery.

## The Rule Model

A rule holds an ordered list of **conditions** and a **match** mode saying how they
combine, plus what to do when it matches:

```
Rule
  match: "all" | "any"            # default "all"
  conditions: [Condition, ...]    # 1 to 16, ordered
  action, webhook_url_override, add_tags, preserve_raw

Condition
  field: str                      # see Rule Fields
  operator: str                   # see Rule Operators
  value: str                      # required, non-empty; may be omitted only for exists
  case_sensitive: bool            # default false
  negate: bool                    # default false
```

- **`all`** matches when every condition is true; **`any`** when at least one is.
- Conditions are evaluated in their stored order and stop at the first one that
  decides: the first false condition under `all`, the first true one under `any`.
  Order never changes the result, only how much work is done.
- **`negate`** inverts a condition.
- There is a single level: no nesting of `all` inside `any`. An `any` rule is
  equivalent to several one-condition rules in the same ruleset; what `all` and
  `negate` add is AND and NOT.
- A rule needs at least one condition and may hold at most 16. The API refuses an
  empty list or a longer one with a 422, and checks each `regex` condition on its own.

Rules in a ruleset still combine as before: every matching rule contributes (unless
the ruleset sets `stop_on_match`), as described in
[Where it sits among the other rule outcomes](#where-it-sits-among-the-other-rule-outcomes).

### A missing field is false, so its negation is true

A condition on a field the message does not have - an absent `header:X-Foo`, for
instance - is **false**, whatever its operator. With `negate` it is therefore
**true**. Two consequences that are easy to trip over:

- `negate` + `exists` means "the field is absent": `NOT header:Auto-Submitted exists`
  holds for a message without that header.
- `NOT header:X-Foo contains bar` holds for a message **without** `X-Foo`, not only for
  one whose `X-Foo` lacks `bar`. If the rule must only apply when the header is there,
  add a positive `header:X-Foo exists` condition under `all`.

### Negating a multi-valued field means "no part matches"

`attachment_names` and `attachment_types` hold one value per part. A positive condition
on them is true when **any** part matches (see
[Matching on attachments](#matching-on-attachments)). A negated one is true when **no**
part matches, so `NOT attachment_names ends_with .exe` holds for a message whose parts
are `a.pdf` and `c.txt`, and fails as soon as one part is `b.exe`. It does not mean
"some part does not end in `.exe`", which would be true for almost every message
carrying more than one part. A message with no parts satisfies every negated
attachment condition.

### Example: a mail-loop guard

An application sends automated mail from its own addresses through an ESP, and a
downstream mail-flow rule copies it back to the inbound address FastSMTP serves. To
drop that copy - and only that copy - the rule has to say **from one of our sending
addresses** AND **marked `Auto-Submitted`, other than `no`**:

```bash
fsmtp rules create <domain-id> "Own automated mail" --priority 100
fsmtp rules rule create <domain-id> <ruleset-id> \
  --match all \
  --condition 'from regex ^(noreply|support)@example\.com$' \
  --condition 'header:Auto-Submitted exists' \
  --not-condition 'header:Auto-Submitted equals no' \
  --action drop
```

No single condition expresses it: `from equals noreply@example.com` would also drop
human-written mail from that mailbox, and `header:Auto-Submitted exists` every
out-of-office the consumer wants. The same request through the API:

```json
{
  "match": "all",
  "conditions": [
    {"field": "from", "operator": "regex", "value": "^(noreply|support)@example\\.com$"},
    {"field": "header:Auto-Submitted", "operator": "exists"},
    {"field": "header:Auto-Submitted", "operator": "equals", "value": "no", "negate": true}
  ],
  "action": "drop"
}
```

### Why a rule did or did not match

At `DEBUG` level the engine logs, for every rule it evaluates, whether it matched and
which condition decided it, by index, field and operator:

```
Rule 3f2a... did not match (match=all): decided by conditions[2] NOT header:Auto-Submitted equals
```

The value is left out of the line, since it can be long.

### The flat fields are deprecated

Before compound conditions, a rule carried a single condition as top-level `field`,
`operator`, `value` and `case_sensitive`. They still work, for one release:

- **Requests.** `POST .../rules` accepts the flat fields and stores them as a
  one-condition rule. `PUT /domains/{id}/rules/{rule_id}` accepts them to edit a rule's
  only condition in place, and refuses them with a 422 on a rule holding several
  conditions or a negated one, which they cannot describe. Sending the flat fields
  together with `conditions` is a 422, and that includes sending back a rule just read:
  a response echoes the flat fields, so a client that GETs a rule, edits `conditions`
  and PUTs the object back must drop `field`, `operator`, `value` and
  `case_sensitive` first.
- **Responses.** Every rule response carries `match` and `conditions`. A rule holding
  exactly one non-negated condition also echoes it in the flat fields; for any other
  rule they are `null`. The OpenAPI schema marks them deprecated.

Read and write `conditions` in new clients. Upgrading to this version needs migration
`009` (`fastsmtp db upgrade head`), which turns every stored rule into a one-condition
rule that evaluates exactly as before. Downgrading past it is refused while any rule
holds more than one condition or a negated one, since dropping a condition would make
the rule match more mail.

## Rule Fields

- `from`, `to`, `subject`, `body` - `from`, `to` and `subject` match the decoded,
  unfolded text, so `subject contains Coupure` matches a subject the sending client
  wrote as RFC 2047 encoded-words; see [Decoded header fields](webhooks.md#decoded-header-fields)
- `header:<name>` (e.g., `header:X-Priority`) - matches the undecoded value, encoded-words
  and folding included, as the payload's `headers` object carries it. For a header that
  appears more than once, both read the **first** occurrence, the one added nearest to
  FastSMTP; see [Repeated headers](webhooks.md#repeated-headers)
- `has_attachment` - inline images that the HTML body actually renders, such as
  signature logos, are delivered in the webhook payload but do not set this
  field. Everything else the message carries does, including a part that claims
  an inline disposition without being referenced from the body; see
  [Inline images and Content-ID](webhooks.md#inline-images-and-content-id)
- `attachment_names`, `attachment_types` - the filename and content type of each
  part the message carries; see [Matching on attachments](#matching-on-attachments).
  Filenames are decoded, as described in
  [Decoded header fields](webhooks.md#decoded-header-fields)
- `dkim_result`, `spf_result` - a mechanism this rule's own domain does not verify
  reads as `none`, whatever another recipient's domain asked for; see
  [Per-domain overrides](configuration.md#per-domain-overrides)

### Rules written against encoded-words

Before `from`, `to` and `subject` were decoded, they matched the raw header, so a rule
could only catch a non-ASCII subject by matching its encoding, for example
`subject regex ^=\?utf-8\?`. Such a rule no longer matches through those fields after
upgrading. Rewrite it either against the decoded text, or against `header:Subject`
(`header:From`, `header:To`), which still reads the raw value.

### Matching on attachments

`attachment_names` and `attachment_types` hold one value per part rather than one per
message, and a rule matches when **any single part** satisfies the condition. So this
fires whether the executable arrives first, last, or alone:

```bash
fsmtp rules rule create <domain-id> <ruleset-id> \
  --field attachment_names \
  --operator regex \
  --value '\.(exe|scr|vbs|js)$' \
  --action forward \
  --webhook-url https://n8n.example.com/webhook/mail-inspect
```

Per-part matching is why these are not one joined string. Against `a.pdf` then `b.exe`
an `ends_with ".exe"` would pass, and against `b.exe` then `a.pdf` it would fail - the
rule would silently test whichever part sorted last while reading as though it tested
all of them. For the same reason a pattern cannot match across a boundary: two parts
named `a.pdf` and `b.exe` do not contain `pdfb`.

A message carrying no parts matches nothing, `exists` included.

Unlike `has_attachment`, these fields include inline images the body renders. A rule is
where policy is expressed, so nothing the message carries is hidden from it - a part
able to hide from matching would be worth more to a sender than a signature logo is to
anyone else.

### Both fields are sender-controlled

Treat them as a way to narrow what gets inspected, not as a verdict. A filename tells
you what the sender chose to call the file: it does not survive `invoice.pdf.exe`, a
right-to-left override rendering a `.exe` as a `.pdf`, or anything inside an archive.
A content type is likewise whatever the sender typed, and need not describe the bytes.

Deciding whether a file is dangerous means reading magic bytes, unpacking archives and
running a scanner, which belongs in the consumer. What these fields buy is routing the
candidates there cheaply.

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

`--field/--operator/--value` is the one-condition shorthand; `--condition` and
`--not-condition` (repeatable) build a compound rule, as in
[the loop guard](#example-a-mail-loop-guard).

Rules are appended to the end of the ruleset and evaluated in that order; use
`fsmtp rules rule reorder <domain-id> <ruleset-id> <rule-id>...` to change it.

Rules can also be managed through the [REST API](api.md).
