# Webhook Payload

When an email is received, FastSMTP sends a POST request to the configured webhook. The payload structure depends on your attachment storage configuration.

## Inline Storage (Default)

With `FASTSMTP_ATTACHMENT_STORAGE=inline` (default), attachments are base64-encoded directly in the payload:

```json
{
  "message_id": "<abc123@sender.com>",
  "from": "sender@example.com",
  "to": "recipient@yourdomain.com",
  "subject": "Invoice for January",
  "date": "Mon, 06 Jan 2025 10:00:00 +0000",
  "envelope_from": "sender@example.com",
  "envelope_to": ["recipient@yourdomain.com"],
  "headers": {
    "Received": "from mx.example.com by mx.yourdomain.com; Mon, 06 Jan 2025 10:00:01 +0000",
    "From": "John Doe <sender@example.com>",
    "To": "recipient@yourdomain.com",
    "Subject": "Invoice for January",
    "Content-Type": "multipart/mixed"
  },
  "header_list": [
    ["Received", "from mx.example.com by mx.yourdomain.com; Mon, 06 Jan 2025 10:00:01 +0000"],
    ["From", "John Doe <sender@example.com>"],
    ["To", "recipient@yourdomain.com"],
    ["Subject", "Invoice for January"],
    ["Content-Type", "multipart/mixed"]
  ],
  "body_text": "Please find attached the invoice for January 2025.",
  "body_html": "<p>Please find attached the invoice for January 2025.</p>",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "disposition": "attachment",
      "size": 45678,
      "content": "JVBERi0xLjQKJeLjz9MKMyAwIG9iago8PC9UeXBlL..."
    }
  ],
  "dkim_result": "pass",
  "dkim_domain": "example.com",
  "spf_result": "pass",
  "spf_domain": "example.com",
  "client_ip": "203.0.113.50",
  "tags": []
}
```

## Decoded header fields

`from`, `to`, `cc`, `reply_to` and `subject` are decoded for display and matching.
RFC 2047 encoded-words are decoded to Unicode, folded lines are unfolded, and raw UTF-8
(RFC 6532) headers are decoded as UTF-8. For a message sent with these headers:

```
From: =?iso-8859-1?Q?J=E9r=F4me?= Dupont <jd@example.com>
Cc: =?utf-8?B?RHVwb250LCBKZWFu?= <a@example.com>
Subject: =?utf-8?B?Q291cHVyZSBkZSBzZXJ2aWNl?=
 =?utf-8?Q?_pr=C3=A9vue?= demain
```

the payload carries (non-ASCII shown as JSON escapes):

```json
{
  "from": "J\u00e9r\u00f4me Dupont <jd@example.com>",
  "cc": "\"Dupont, Jean\" <a@example.com>",
  "subject": "Coupure de service pr\u00e9vue demain",
  "headers": {
    "From": "=?iso-8859-1?Q?J=E9r=F4me?= Dupont <jd@example.com>",
    "Cc": "=?utf-8?B?RHVwb250LCBKZWFu?= <a@example.com>",
    "Subject": "=?utf-8?B?Q291cHVyZSBkZSBzZXJ2aWNl?=\r\n =?utf-8?Q?_pr=C3=A9vue?= demain"
  }
}
```

- **`headers` stays undecoded.** It holds every header with its encoded-words and folds
  intact, for anything that needs the wire form; for a repeated header, see
  [Repeated headers](#repeated-headers). `date` and `message_id` are also passed
  through unchanged. A header sent as raw UTF-8 (RFC 6532) arrives as that text; bytes
  that are not valid UTF-8 become U+FFFD, since JSON cannot carry them. For a byte-exact
  copy of the message (DKIM, archival, replay), use
  [Preserved Raw Message](#preserved-raw-message).
- **Addresses are kept as sent.** Only encoded-words in display names and comments
  are decoded. Addresses, comments (including the legacy `addr (Name)` form) and
  malformed values are left as they arrived. An encoded-word anywhere else - inside
  `<...>`, in a quoted local-part, or in an address with no `<...>` after it - is part
  of the address (RFC 2047 forbids one there) and stays encoded, so an encoded
  `boss@corp.com` can never pass for a sender. A decoded display name that contains a
  comma, `@`, `<` or another special character is quoted, as with `Cc` above. As a
  final check, the field is parsed before and after decoding; if the addresses differ
  at all, the field is delivered undecoded.
- **Bad charsets do not fail delivery.** An unknown or mislabelled charset decodes with
  U+FFFD replacement characters instead of raising.
- **Decoded text is made safe.** This applies to these fields and to attachment
  filenames, whether the text arrived encoded or as raw UTF-8. Control characters and
  line separators (CR, LF, NEL, U+2028, U+2029), bidi overrides, embeddings and isolates
  (U+202A-U+202E, U+2066-U+2069), and lone surrogates are neutralised, so nothing can
  put a line break into a field or make it render reversed. In `subject` and filenames
  controls become spaces and bidi characters are removed. In the address fields every
  one of them becomes U+FFFD instead, because removing a character could turn one
  mailbox into another (`ceo<U+2066>@corp.com` into `ceo@corp.com`).
- **Rules match the decoded text.** The `from`, `to` and `subject` rule fields read these
  same decoded values; `header:<name>` reads the raw one. See
  [Rule Fields](rules.md#rule-fields).

### This changes the payload for existing consumers

Before this change those five fields carried the wire value, encoded-words and folds
included. A consumer that already decodes them mostly sees no difference, since
decoding text that has no encoded-words leaves it unchanged. The exception is a display
name that decodes to something needing quotes, which now arrives quoted. A consumer
that relied on the raw form there - to compare against a stored raw string, say -
should read the field from `headers` instead.

`headers` changes too, for raw UTF-8 headers only. Each of their non-ASCII bytes used to
arrive as its own U+FFFD, so `\u00e9t\u00e9` was delivered as four replacement
characters around a `t`. It now arrives as the text that was sent. The same fix applies
to `header:<name>` rules, which could not match non-ASCII text in such a header before.

Attachment `filename` values change the same way. A name sent as raw UTF-8 used to lose
its non-ASCII bytes the same way, and a name written as an RFC 2047 encoded-word inside
quotes (`filename="=?utf-8?Q?caf=C3=A9.pdf?="`, which Outlook and many libraries
send) arrived undecoded. Both now arrive as the name that was meant (`caf\u00e9.pdf`),
as an RFC 2231 name (`filename*=utf-8''caf%C3%A9.pdf`) already did. The S3 object
key is built from the filename, so new uploads of such attachments get a different
key; objects already stored keep theirs.

The same applies to rules: see
[Rules written against encoded-words](rules.md#rules-written-against-encoded-words).

## Repeated headers

`headers` is a JSON object, so it holds one value per name. For a header that appears
more than once it holds the **first** occurrence, as received from the top of the
message, and keeps the spelling of the name it first arrived with. `header_list` holds
every header as a `[name, value]` pair, in the order received, repeats included, so
a consumer that needs every `Received` or `Authentication-Results` line reads it from
there. Values in both are undecoded.

First, not last, because the headers that legitimately repeat are added at the top:

- Each server a message passes through MUST insert its `Received` line "at the
  beginning of the message content" (RFC 5321 section 4.4).
- `Authentication-Results` "MUST be prepended to the message" (RFC 8601 section 4.1).
- Spam and virus filters conventionally prepend their verdicts (`X-Spam-Status` and
  the like); no RFC requires it.

So when FastSMTP sits behind a relay or filter that prepends its own headers, the
first occurrence came from that hop, and the last may be one the sender wrote into
their own message: a sender can put `Authentication-Results: ... dkim=pass` or
`X-Spam-Flag: NO` at the bottom, below the real verdict added upstream.
`header:<name>` rules read the first occurrence too, so a rule and `headers` always
see the same value.

**Headers are not authenticated.** FastSMTP does not add its own `Received` or
`Authentication-Results` line, and does not remove forged ones. When it is the
internet-facing MX, nothing upstream prepends anything, so every header, first or
last, is whatever the sender wrote. For authentication, use the payload's own
`dkim_result`, `dkim_domain`, `spf_result` and `spf_domain`, which FastSMTP computed
itself. Trust a header's first occurrence only when you know which relay added it.

Fields that RFC 5322 section 3.6 allows only once (`From`, `To`, `Subject`,
`Message-ID`, `Date` and others) have no right answer when repeated: the message is
malformed. Reading the first one everywhere at least keeps `from` and
`headers["From"]` in agreement.

### This changes `headers` for existing consumers

Before this change `headers` held the **last** occurrence of a repeated header. A
consumer that relied on that sees the first one now. One that needs a specific
occurrence should read `header_list`, which is new and does not replace `headers`.

Header names are also matched case-insensitively now. RFC 5322 defines each name as a
quoted literal in its grammar (`"Date:"`), and section 1.2.2 makes those literals
case-insensitive. Before,
`x-spam-status` and `X-Spam-Status` in one message were two separate keys in `headers`.
Now there is one key, spelled as the first occurrence arrived, so look keys up
case-insensitively.
The test payload sent by `POST /api/v1/test-webhook` carries `header_list` too.

## S3 Storage

With `FASTSMTP_ATTACHMENT_STORAGE=s3`, attachments are uploaded to S3 and the payload contains bucket/key references:

```json
{
  "message_id": "<abc123@sender.com>",
  "from": "sender@example.com",
  "to": "recipient@yourdomain.com",
  "subject": "Invoice for January",
  "date": "Mon, 06 Jan 2025 10:00:00 +0000",
  "envelope_from": "sender@example.com",
  "envelope_to": ["recipient@yourdomain.com"],
  "headers": {
    "From": "John Doe <sender@example.com>",
    "To": "recipient@yourdomain.com",
    "Subject": "Invoice for January"
  },
  "header_list": [
    ["From", "John Doe <sender@example.com>"],
    ["To", "recipient@yourdomain.com"],
    ["Subject", "Invoice for January"]
  ],
  "body_text": "Please find attached the invoice for January 2025.",
  "body_html": "<p>Please find attached the invoice for January 2025.</p>",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "disposition": "attachment",
      "size": 45678,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/abc123@sender.com/7f3a9c21-invoice-2025-01.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/abc123@sender.com/7f3a9c21-invoice-2025-01.pdf"
    }
  ],
  "dkim_result": "pass",
  "dkim_domain": "example.com",
  "spf_result": "pass",
  "spf_domain": "example.com",
  "client_ip": "203.0.113.50",
  "tags": []
}
```

## S3 Storage with Presigned URLs

With `FASTSMTP_S3_PRESIGNED_URLS=true`, the payload includes time-limited download URLs:

```json
{
  "message_id": "<abc123@sender.com>",
  "from": "sender@example.com",
  "to": "recipient@yourdomain.com",
  "subject": "Invoice for January",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "disposition": "attachment",
      "size": 45678,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/abc123@sender.com/7f3a9c21-invoice-2025-01.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/abc123@sender.com/7f3a9c21-invoice-2025-01.pdf",
      "presigned_url": "https://my-email-attachments.s3.us-west-2.amazonaws.com/attachments/yourdomain.com/abc123@sender.com/7f3a9c21-invoice-2025-01.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20250106%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250106T100000Z&X-Amz-Expires=3600&X-Amz-Signature=abc123..."
    }
  ]
}
```

## Preserved Raw Message

When raw message preservation is enabled for a recipient, the payload carries a
`raw_message` block pointing at the complete MIME message archived in S3:

```json
{
  "message_id": "<abc123@sender.com>",
  "from": "billing@sender.com",
  "to": "invoices@yourdomain.com",
  "subject": "Invoice 2025-01",
  "raw_message": {
    "storage": "s3",
    "bucket": "my-email-archive",
    "key": "raw/yourdomain.com/2026/03/07/abc123@sender.com.eml",
    "url": "https://s3.us-west-2.amazonaws.com/my-email-archive/raw/yourdomain.com/2026/03/07/abc123@sender.com.eml",
    "size": 48213,
    "presigned_url": "https://..."
  }
}
```

The archived object is the raw bytes exactly as received, stored as `message/rfc822`, so
it can be fed straight back into any MIME parser. `presigned_url` is present only when
`FASTSMTP_S3_PRESIGNED_URLS=true`. The block is absent when preservation is off for the
recipient, or when an optional archive upload failed. See
[Raw Message Preservation](configuration.md#raw-message-preservation-s3) for how
preservation is enabled per domain and per rule.

The `key` is unique per message. A Message-ID that is absent, empty, or present but
degenerate (`<>`) is replaced with a generated one before the key is built, so two
messages never share an archive object and silently overwrite one another. Consumers may
therefore treat `key` as a stable per-message identifier. The block itself is still
optional -- absent when preservation is off, or when an optional upload failed -- so
check for it before reading `key`.

## S3 Fallback to Inline

If S3 upload fails, FastSMTP gracefully falls back to inline storage. The attachment will have `storage_fallback: true` to indicate this:

```json
{
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
      "disposition": "attachment",
      "size": 45678,
      "storage_fallback": true,
      "content": "JVBERi0xLjQKJeLjz9MKMyAwIG9iago8PC9UeXBlL..."
    }
  ]
}
```

## Multiple Attachments Example

```json
{
  "message_id": "<xyz789@sender.com>",
  "from": "hr@company.com",
  "to": "onboarding@yourdomain.com",
  "subject": "New Employee Documents",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "offer-letter.pdf",
      "content_type": "application/pdf",
      "disposition": "attachment",
      "size": 89012,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/e4b8f01d-offer-letter.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/e4b8f01d-offer-letter.pdf",
      "presigned_url": "https://..."
    },
    {
      "filename": "headshot.jpg",
      "content_type": "image/jpeg",
      "disposition": "attachment",
      "size": 234567,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/58e2a94f-headshot.jpg",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/58e2a94f-headshot.jpg",
      "presigned_url": "https://..."
    },
    {
      "filename": "w4-form.pdf",
      "content_type": "application/pdf",
      "disposition": "attachment",
      "size": 56789,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/9d1c6b73-w4-form.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/9d1c6b73-w4-form.pdf",
      "presigned_url": "https://..."
    }
  ]
}
```

## Which parts are the body

Only two content types are ever the body: `text/plain` goes to `body_text` and
`text/html` to `body_html`, unless the part is marked `Content-Disposition: attachment`
or has a filename on its `Content-Disposition`, which makes it a file. nodemailer's
`mailparser` draws the same line. Every other part is either captured in `attachments`
with its decoded bytes or skipped:

- **Other `text/*` types are files.** A `text/calendar` meeting invite or a `text/csv`
  export is captured, with a fallback filename such as `part-1.ics` if it has none. Its
  `disposition` is `inline` if it says so or has a `Content-ID`, otherwise `attachment`.
  Two kinds of container are the exception:
  - Inside `multipart/alternative`, each part is another version of the same content
    (RFC 2046 section 5.1.4), so a text alternative such as Gmail's `text/x-amp-html`
    or Apple Mail's `text/watch-html` is skipped, not captured. `text/calendar` is
    still captured there: Outlook sends meeting invites as an alternative.
  - Inside `multipart/report` (a bounce), text parts such as `text/rfc822-headers`
    are report data and are skipped.
- **Non-text parts are files** when they have a `Content-Disposition`, a name or a
  `Content-ID`, and a forwarded message (`message/rfc822`) always is.
- **Skipped:** a `message/delivery-status` part with no disposition or Content-ID, which
  is report data rather than a file, and, inside multipart mail, a non-text part with no
  disposition, name or Content-ID. `application/pgp-signature` arrives exactly like
  that and is not an attachment.

### Single-part messages

A message that is not multipart has exactly one part, and the same rules apply, plus
one: a lone non-text part has no body to belong to, so it is captured even with no
disposition, name or Content-ID. A lone PDF, an image sent on its own by a scanner, or
a bare `application/json` arrives in `attachments`, and `body_text` and `body_html`
are empty, so a `body` rule no longer sees it; `attachment_names`, `attachment_types`
and `has_attachment` do. A lone `message/*` part other than `message/rfc822` is still
not captured.

### Changes from v0.8.0

Up to v0.8.0:

- A single-part message was always decoded into `body_text`. A lone PDF or image
  arrived as replacement characters, with no attachment and `has_attachments: false`,
  and a bare calendar invite arrived as iCalendar source in `body_text`.
- Inside multipart mail, a `text/*` part other than plain or html with no filename on
  its `Content-Disposition` was dropped: a meeting invite with no disposition never
  reached the consumer. It is now captured, except for the text alternatives and
  report parts described above, which are still skipped.

## Inline Images and Content-ID

HTML mail embeds images by reference rather than by value: the body carries
`<img src="cid:image001.png@01DA1234.5678">` and a sibling MIME part carries the
matching `Content-ID` header. Outlook and Apple Mail both do this for signature
logos.

Those parts appear in `attachments` alongside ordinary attachments, and are told
apart by two fields:

| Field | Meaning |
|---|---|
| `disposition` | `attachment` or `inline`. Present on every entry. |
| `content_id` | The `Content-ID` addr-spec with the angle brackets stripped, so it matches the `cid:` URL in `body_html` directly. Present only on parts that carry the header. |

`content_id` is independent of `disposition`: clients mark cid-referenced images
`attachment` about as often as `inline`, so match on `content_id` rather than on
`disposition` when resolving a `cid:` reference.

```json
{
  "body_html": "<html><body><p>Regards,</p><img src=\"cid:image001.png@01DA1234.5678\"></body></html>",
  "has_attachments": false,
  "attachments": [
    {
      "filename": "image001.png",
      "content_type": "image/png",
      "disposition": "inline",
      "content_id": "image001.png@01DA1234.5678",
      "size": 4523,
      "storage": "inline",
      "content": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ...",
      "content_transfer_encoding": "base64"
    }
  ]
}
```

Inline parts go through the same storage path as attachments: S3 when it is
configured, base64 `content` when it is not, metadata only when the part exceeds
`FASTSMTP_WEBHOOK_MAX_INLINE_ATTACHMENT_SIZE`.

### `content_id` is sender-controlled

The header comes from the message, so treat the field as untrusted input and
HTML-escape it before putting it anywhere near a rendered page. A well-formed
Content-ID is an addr-spec, so FastSMTP omits the field entirely when the value
carries quotes, angle brackets, whitespace or control characters, or runs past
512 characters. An entry with no `content_id` is a part whose header was absent
or malformed.

### `has_attachments` counts what the body does not render

Note `"has_attachments": false` in the example above. A signature logo is not an
attachment as far as your users are concerned, and treating it as one would fire
attachment rules on a large share of ordinary mail. What earns the exemption is
looking like a decoration on all three counts. A captured part sets
`has_attachments` unless

- its `disposition` is `inline` (or it has no disposition header of its own),
  **and**
- its `content_type` is an `image/*`, **and**
- it has a `content_id` that `body_html` actually references.

Declaring an inline disposition is not enough on its own; neither is declaring a
`content_id` that nothing references; and neither is the reference by itself,
since a `<div style="display:none">` around an `<img>` renders nothing and would
otherwise exempt any file at all. Parts with an explicit `attachment`
disposition always count, referenced or not, since clients routinely mark cid
images that way.

None of this is airtight, because every input is sender-controlled - a file
labelled `image/png` passes the type test. What it buys is that anything
claiming the exemption is something a mail client would draw rather than offer
as an attachment, and the part's real filename still reaches you in the payload.
Treat `has_attachments` as a routing signal, not a security boundary: inspect
`attachments` yourself when the decision matters.

The same rule backs the `has_attachment` rule condition. To find inline images
regardless of how they were labelled, look for entries that carry a
`content_id`.

### Oversized messages leave dangling references

When a payload exceeds `FASTSMTP_WEBHOOK_MAX_INLINE_PAYLOAD_SIZE`, FastSMTP
drops attachment `content` before it truncates the bodies, since that is the one
field it can remove without corrupting anything. The attachment entry and its
`content_id` survive, so a `cid:` reference resolves to an entry with no bytes
behind it. Render a placeholder for an entry that has a `content_id` but no
`content`, `url` or `presigned_url`.

If dropping the attachment content is not enough on its own, the bodies are
truncated too, and truncation keeps the start of `body_html` and cuts the end.
Signature images live in the footer, so on a message that large the `cid:`
reference can be cut away entirely and the attachment entry left with nothing
pointing at it. Do not assume every entry carrying a `content_id` has a matching
reference in the body.

## Forwarded Messages

A forwarded email arrives as an attached `message/rfc822` part, whose payload is the
complete original message, headers and all. Most clients mark it `attachment`; one that
sends it with no disposition header at all is still treated as an attachment, since a
message part is never body content.
FastSMTP represents it as exactly one entry in `attachments`; it does not walk into
the forwarded message's own parts.

```json
{
  "from": "alice@example.com",
  "subject": "Fwd: Quarterly numbers",
  "body_text": "See attached.",
  "has_attachments": true,
  "attachments": [
    {
      "filename": "Quarterly numbers.eml",
      "content_type": "message/rfc822",
      "disposition": "attachment",
      "size": 48213,
      "storage": "inline",
      "content": "RnJvbTogYm9iQGV4YW1wbGUuY29tClN1YmplY3Q6IFF1YXJ0ZXJseSBudW1iZXJzCg==...",
      "content_transfer_encoding": "base64"
    }
  ]
}
```

`content` is the forwarded message serialized back to RFC 5322 form and base64-encoded -
the same shape as the `.eml` object in [Preserved Raw Message](#preserved-raw-message),
though not byte-identical to what the sender transmitted, since it is re-serialized from
the parsed message rather than sliced out of the wire bytes. Use
`FASTSMTP_PRESERVE_RAW_MESSAGE` when you need the original octets.
It goes through the same storage path as any other attachment: S3 when configured,
base64 `content` when it is not, metadata only when it exceeds
`FASTSMTP_WEBHOOK_MAX_INLINE_ATTACHMENT_SIZE`. A forwarded message with no filename of
its own falls back to `part-N.eml`, same as any other nameless part (`part-N.u8msg`
for the `message/global` variant). Only `message/rfc822` and `message/global` are
treated this way; a DSN's `message/delivery-status` is report data rather than an
encapsulated message and stays out of `attachments` as it always has. A forwarded
message sent with a `Content-Transfer-Encoding` that RFC 2045 forbids for `message/*`
arrives as a metadata-only entry, since the bytes the parser holds are the undecoded
text rather than the message. `has_attachments`
is `true` whenever a forwarded message is present, since its `attachment` disposition
always counts (see [`has_attachments` counts what the body does not render](#has_attachments-counts-what-the-body-does-not-render)).

Two things follow from not walking into the forwarded message:

- `body_text` and `body_html` are always the outer message's own body. The forwarded
  message's body no longer overwrites them - which matters beyond display, since it
  also decides what the `body` rule condition matches against.
- The forwarded message's own attachments and inline images do not appear as separate
  entries in the outer `attachments` array. A consumer that needs them parses the
  `.eml` bytes itself.

### This is a breaking change for existing consumers

Before this fix, payload extraction used `Message.walk()`, which recurses into any
part shaped like a container - and a `message/rfc822` part is, internally, shaped
exactly like one. Its own body, attachments and inline images were yielded as if they
belonged to the outer message: the forwarded message's attachments were hoisted into
the top-level `attachments` array, and the `message/rfc822` entry itself carried no
content at all (`size: 0`, no `content` field - `get_payload(decode=True)` returns
`None` for a `message/*` part). A consumer that downloaded a forwarded attachment
straight from the top-level `attachments` array stops finding it there. It is still
present, inside the `.eml` bytes of the `message/rfc822` entry, just no longer
duplicated at the top level.

## S3 Key Structure

Attachments are stored with the following key structure:

```
{prefix}/{domain}/{message_id}/{content_digest}-{filename}
```

`content_digest` is the first 8 hex characters of the SHA-256 digest of the attachment's
bytes. It disambiguates parts that would otherwise share a key -- two attachments in one
message with the same filename, or a filename that sanitizes down to nothing -- without
changing what `filename` reports to the sender's own value. Two parts with identical bytes
get the same key (a retried upload overwrites its own object as a no-op); two parts with
the same filename but different bytes get different keys, so neither silently overwrites
the other.

For example:

```
attachments/yourdomain.com/abc123@sender.com/7f3a9c21-invoice.pdf
```

`filename` is sanitized before it goes into the key: path separators (`/` and `\`) are
stripped, and a component that would sanitize down to a bare `.` or `..` is replaced, so a
sender-supplied filename cannot place the object outside its own
`{prefix}/{domain}/{message_id}/` namespace.

Preserved raw messages use their own prefix and are partitioned by receive date so S3
lifecycle rules can expire archives by age:

```
{raw_prefix}/{domain}/{YYYY}/{MM}/{DD}/{message_id}.eml
```

For example:

```
raw/yourdomain.com/2026/03/07/abc123@sender.com.eml
```

## Delivery statuses

Every delivery attempt is recorded in the delivery log (`fsmtp ops log list`,
`GET /domains/{id}/delivery-log`). The `status` field moves through these values:

| Status | Meaning |
|--------|---------|
| `pending` | Queued; the worker will send it at `next_retry_at` |
| `delivered` | The webhook answered with a success status |
| `failed` | The last attempt failed and a retry is scheduled (exponential backoff) |
| `exhausted` | Every retry failed; the payload was sent to the DLQ webhook, if one is configured. Terminal |
| `cancelled` | The recipient or its domain was deleted while the delivery was still `pending` or `failed`. Terminal |

A delete cancels queued deliveries immediately, in the same transaction that hides the
recipient or domain, and `last_error` records why (`Recipient deleted` / `Domain
deleted`). A cancelled delivery is not sent: a delivery claimed by a worker just before
the delete is caught by the worker itself and cancelled instead of being posted, and it
never reaches the DLQ. The one bounded exception is a request that was already on the
wire when the delete committed - it completes that single attempt, but `cancelled` is
sticky, so the outcome cannot overwrite it with `failed` or `delivered` and nothing is
retried.

Restoring the recipient or domain does **not** re-queue anything. Each cancelled
delivery is re-armed explicitly with `POST /delivery-log/{id}/retry`
(`fsmtp ops log retry <log-id>`), which answers `409` while the recipient or domain is
still deleted (`Domain is deleted; restore it before retrying` / `Recipient is deleted;
restore it before retrying`), and `409` `Delivery is no longer retryable` when the
delivery left the retryable statuses under the request or its recipient was purged: a
cancelled delivery with no recipient row has no authentication headers to send with, so
it stays cancelled. `cancelled` is counted in
[`fastsmtp_webhook_deliveries_total`](monitoring.md#webhook-delivery) but not in
`fastsmtp_queue_depth`, so cancelling drops the backlog at once.
