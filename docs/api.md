# API Reference

Base URL: `/api/v1`

## Authentication

All API requests require an API key in the header:

```bash
curl -H "X-API-Key: your-api-key" https://fastsmtp.example.com/api/v1/domains
```

## Endpoints

### Operations

- `GET /health` - Health check
- `GET /ready` - Readiness check (database connectivity)
- `POST /test-webhook` - Test a webhook URL

### Domains

- `GET /domains` - List domains
- `POST /domains` - Create domain
- `GET /domains/{id}` - Get domain
- `PUT /domains/{id}` - Update domain
- `DELETE /domains/{id}` - Delete domain

### Recipients

- `GET /domains/{id}/recipients` - List recipients
- `POST /domains/{id}/recipients` - Create recipient
- `PUT /domains/{id}/recipients/{rid}` - Update recipient
- `DELETE /domains/{id}/recipients/{rid}` - Delete recipient

### Rules

- `GET /domains/{id}/rulesets` - List rulesets
- `POST /domains/{id}/rulesets` - Create ruleset
- `POST /domains/{id}/rulesets/{rsid}/rules` - Create rule

### Delivery Logs

- `GET /domains/{id}/delivery-log` - List delivery logs
- `GET /delivery-log/{id}` - Get delivery log details
- `POST /delivery-log/{id}/retry` - Retry failed delivery

!!! info "Interactive documentation"

    Full API documentation is available on a running server at `/docs` (Swagger UI) or `/redoc`.
