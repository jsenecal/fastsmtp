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
      "size": 45678,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf"
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
      "size": 45678,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf",
      "presigned_url": "https://my-email-attachments.s3.us-west-2.amazonaws.com/attachments/yourdomain.com/abc123@sender.com/invoice-2025-01.pdf?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20250106%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20250106T100000Z&X-Amz-Expires=3600&X-Amz-Signature=abc123..."
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

## S3 Fallback to Inline

If S3 upload fails, FastSMTP gracefully falls back to inline storage. The attachment will have `storage_fallback: true` to indicate this:

```json
{
  "attachments": [
    {
      "filename": "invoice-2025-01.pdf",
      "content_type": "application/pdf",
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
      "size": 89012,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/offer-letter.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/offer-letter.pdf",
      "presigned_url": "https://..."
    },
    {
      "filename": "headshot.jpg",
      "content_type": "image/jpeg",
      "size": 234567,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/headshot.jpg",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/headshot.jpg",
      "presigned_url": "https://..."
    },
    {
      "filename": "w4-form.pdf",
      "content_type": "application/pdf",
      "size": 56789,
      "storage": "s3",
      "bucket": "my-email-attachments",
      "key": "attachments/yourdomain.com/xyz789@sender.com/w4-form.pdf",
      "url": "https://s3.us-west-2.amazonaws.com/my-email-attachments/attachments/yourdomain.com/xyz789@sender.com/w4-form.pdf",
      "presigned_url": "https://..."
    }
  ]
}
```

## S3 Key Structure

Attachments are stored with the following key structure:

```
{prefix}/{domain}/{message_id}/{filename}
```

For example:

```
attachments/yourdomain.com/abc123@sender.com/invoice.pdf
```

Preserved raw messages use their own prefix and are partitioned by receive date so S3
lifecycle rules can expire archives by age:

```
{raw_prefix}/{domain}/{YYYY}/{MM}/{DD}/{message_id}.eml
```

For example:

```
raw/yourdomain.com/2026/03/07/abc123@sender.com.eml
```
