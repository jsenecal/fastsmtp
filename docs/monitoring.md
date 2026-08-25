# Monitoring

FastSMTP exposes Prometheus metrics at `GET /metrics` on the API port, in the
standard text exposition format.

```bash
curl http://localhost:8000/metrics
```

The endpoint is served at the root, not under `/api/v1`, and is deliberately
absent from the OpenAPI schema - Prometheus text output is not a JSON API.

!!! warning "The endpoint is unauthenticated"

    `/metrics` requires no API key and is excluded from rate limiting, matching
    the convention Prometheus exporters follow. It reveals how much mail you
    handle, how deep your delivery queue is, how often DKIM and SPF fail, and how
    slow your endpoints are.

    Keep the API port on a private network, or restrict scraping with
    [`FASTSMTP_METRICS_ALLOWED_IPS`](#restricting-access).

## Metrics

### HTTP

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `fastsmtp_requests_total` | Counter | `method`, `endpoint`, `status_code` | HTTP requests served |
| `fastsmtp_request_duration_seconds` | Histogram | `method`, `endpoint` | Request latency (buckets 5ms-10s) |

### SMTP intake

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `fastsmtp_smtp_messages_total` | Counter | `result` = `accepted`/`rejected`/`dropped` | Messages received. `dropped` means accepted then discarded by rules |
| `fastsmtp_smtp_message_size_bytes` | Histogram | - | Message size (buckets 1KB-10MB) |
| `fastsmtp_smtp_rate_limited_total` | Counter | `type` = `connection`/`message`/`recipient` | SMTP requests refused by rate limiting |

### Webhook delivery

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `fastsmtp_webhook_deliveries_total` | Counter | `status` = `delivered`/`failed`/`exhausted`/`cancelled` | Delivery attempts. `exhausted` means retries ran out and the delivery went to the DLQ; `cancelled` means the worker picked up a delivery whose recipient or domain had been deleted and dropped it without sending (no HTTP call, no DLQ) |
| `fastsmtp_webhook_delivery_duration_seconds` | Histogram | - | Delivery latency (buckets 100ms-30s) |
| `fastsmtp_queue_depth` | Gauge | `status` = `pending`/`failed` | Deliveries waiting in the queue. Cancelled deliveries are terminal and not counted |

`cancelled` is a non-delivery, not a failure: a dashboard or alert built on
`status!="delivered"` will count it. Deliveries cancelled at delete time, before any
worker touched them, do not increment the counter at all - only those a worker had
already claimed do. See [Delivery statuses](webhooks.md#delivery-statuses).

### Email authentication

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `fastsmtp_auth_results_total` | Counter | `type` = `dkim`/`spf`, `result` = `pass`/`fail`/`none` | Verification outcomes per message |

### Metrics access

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `fastsmtp_metrics_scrapes_denied_total` | Counter | - | Scrapes refused because the client was not in `FASTSMTP_METRICS_ALLOWED_IPS` |

Only meaningful once an allowlist is configured. It has no source-address label:
that would be unbounded cardinality, and the address appears in the log line
instead.

## Restricting access

Two settings control who may scrape. Both accept bare addresses and CIDR
prefixes, in either address family.

| Variable | Default | Description |
|----------|---------|-------------|
| `FASTSMTP_METRICS_ALLOWED_IPS` | *(empty)* | Addresses allowed to scrape. Empty leaves the endpoint unrestricted |
| `FASTSMTP_METRICS_TRUSTED_PROXIES` | *(empty)* | Proxies whose `X-Forwarded-For` may be believed. Empty means the header is never trusted |

```bash
export FASTSMTP_METRICS_ALLOWED_IPS='["10.0.0.0/8","192.0.2.5","2001:db8::/32"]'
```

A refused scrape gets `403` and no metric data. Malformed entries are rejected at
startup rather than skipped - an allowlist that silently drops a typo is worse
than none, because it looks enforced while standing open.

Refusals are logged at WARNING, but **throttled**: the first denial in each
60-second window is logged with its source address, and the rest are counted and
reported when the window rolls over. `/metrics` needs no credential and is
excluded from rate limiting, so logging every refusal would let any client drive
unbounded log volume. `fastsmtp_metrics_scrapes_denied_total` is not throttled,
so alert on that for the true rate.

### Behind a reverse proxy

By default the check uses the **socket peer**, so behind an ingress every request
appears to come from the proxy. Naming the proxy in
`FASTSMTP_METRICS_TRUSTED_PROXIES` makes FastSMTP read the real client from
`X-Forwarded-For` instead:

```bash
export FASTSMTP_METRICS_TRUSTED_PROXIES='["10.9.0.0/16"]'
export FASTSMTP_METRICS_ALLOWED_IPS='["10.20.0.0/16"]'
```

`X-Forwarded-For` is attacker-controlled, so it is consulted **only** when the
peer is a listed proxy, and the chain is read from the right - discarding trusted
hops and taking the first untrusted entry. The leftmost entry is whatever the
original caller chose to send and is never used.

The two settings answer different questions. Trusting a proxy does not allow it
to scrape; it only lets it assert who the client is. List anything there with
care: a trusted proxy can claim any client address.

!!! danger "Running your own ASGI server"

    FastSMTP resolves `X-Forwarded-For` itself, so `fastsmtp serve` starts uvicorn
    with `proxy_headers=False`. If you run the app yourself - `uvicorn
    fastsmtp.main:app`, gunicorn with a uvicorn worker, or any wrapper - **you
    must disable proxy headers there too**.

    uvicorn enables them by default and rewrites the peer address from the
    *leftmost* `X-Forwarded-For` entry, which the caller controls. Leave that on
    and the allowlist checks a forged value:

    ```bash
    uvicorn fastsmtp.main:app --no-proxy-headers
    ```

    This matters most with `FORWARDED_ALLOW_IPS=*`, a common container setting  - 
    but uvicorn's default of `127.0.0.1` is also bypassable by anything sharing
    the host, such as another container on the same network namespace.

### Unix socket deployments

The allowlist needs a peer address. When the app is served over a Unix domain
socket behind nginx, there is none, so every scrape is refused once
`FASTSMTP_METRICS_ALLOWED_IPS` is set - `metrics_trusted_proxies` cannot help,
because there is no peer to match against it.

Restrict scraping in nginx instead, and leave `FASTSMTP_METRICS_ALLOWED_IPS`
empty for socket-served deployments.

## Prometheus configuration

```yaml
scrape_configs:
  - job_name: fastsmtp
    scrape_interval: 15s
    static_configs:
      - targets: ["fastsmtp:8000"]
```

Add `metrics_path` only if you front the service with a path prefix; the default
`/metrics` is correct otherwise.

### Queries worth having

```promql
# Message intake by outcome
sum by (result) (rate(fastsmtp_smtp_messages_total[5m]))

# Webhook failure ratio (excludes cancelled: those were never attempted)
sum(rate(fastsmtp_webhook_deliveries_total{status=~"failed|exhausted"}[5m]))
  / sum(rate(fastsmtp_webhook_deliveries_total{status!="cancelled"}[5m]))

# Queue backlog - rising means delivery is not keeping up with intake
fastsmtp_queue_depth{status="pending"}

# 95th percentile webhook latency
histogram_quantile(0.95, sum by (le) (
  rate(fastsmtp_webhook_delivery_duration_seconds_bucket[5m])
))

# Authentication failure rate
sum by (type) (rate(fastsmtp_auth_results_total{result="fail"}[5m]))
```

### Alerts worth having

| Condition | Why |
|-----------|-----|
| `fastsmtp_queue_depth{status="pending"}` rising steadily | Delivery is falling behind intake; with `FASTSMTP_QUEUE_MAX_PENDING` set, new mail will eventually be rejected |
| `fastsmtp_webhook_deliveries_total{status="exhausted"}` increasing | Deliveries are being abandoned. Pair with `FASTSMTP_DLQ_WEBHOOK_URL` so the payloads are not lost |
| `fastsmtp_smtp_rate_limited_total` increasing | Either a misconfigured limit or a sender hammering the server |
| `fastsmtp_metrics_scrapes_denied_total` increasing | Something is repeatedly trying to scrape metrics it is not allowed to. Also worth checking after changing the allowlist, in case a legitimate scraper was locked out |

## Health checks

Separate from metrics, for load balancers and orchestrators:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/health` | Liveness. Returns `200` if the process is running |
| `GET /api/v1/ready` | Readiness. Returns `200` when the database is reachable, `503` otherwise |

Both are unauthenticated and excluded from rate limiting. Use `/ready` as the
readiness probe so a pod with a broken database connection is removed from
service rather than handed traffic.
