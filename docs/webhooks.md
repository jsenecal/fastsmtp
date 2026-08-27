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
    "From": "John Doe <sender@example.com>",
    "To": "recipient@yourdomain.com",
    "Subject": "Invoice for January",
    "Content-Type": "multipart/mixed"
  },
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
being rendered: a `cid:` URL in `body_html` pointing at that part's
`content_id`. Specifically, a captured part sets `has_attachments` unless

- its `disposition` is `inline` (or it has no disposition header of its own),
  **and**
- it has a `content_id` that `body_html` actually references.

Declaring an inline disposition is not enough on its own, and neither is
declaring a `content_id` that nothing references - otherwise any sender could
exempt a file from `has_attachment` rules just by labelling it. Parts with an
explicit `attachment` disposition always count, referenced or not, since clients
routinely mark cid images that way.

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
