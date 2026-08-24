# API Reference

Base URL: `/api/v1`

## Authentication

All API requests require an API key in the header:

```bash
curl -H "X-API-Key: your-api-key" https://fastsmtp.example.com/api/v1/domains
```

## Endpoints

Routes marked `?include_deleted` and `?purge` take those boolean query parameters;
see [Deletion, restore and purge](#deletion-restore-and-purge) for what they do and
who may pass them.

### Operations

- `GET /health` - Health check
- `GET /ready` - Readiness check (database connectivity; `?include_queue`, `?include_smtp`)
- `POST /test-webhook` - Test a webhook URL

### Auth

All routes act on the caller's own account and keys.

- `GET /auth/me` - Current user and domain memberships (memberships of deleted domains are omitted)
- `GET /auth/keys?include_deleted` - List your API keys
- `POST /auth/keys` - Create an API key
- `DELETE /auth/keys/{id}` - Delete an API key (soft; a deleted key answers 404 afterwards)
- `POST /auth/keys/{id}/rotate` - Rotate an API key (the old key is deleted)

### Users

Superuser only.

- `GET /users?include_deleted` - List users
- `POST /users` - Create user
- `GET /users/{id}?include_deleted` - Get user
- `PUT /users/{id}` - Update user
- `DELETE /users/{id}?purge` - Delete user (soft), or purge an already-deleted one
- `POST /users/{id}/restore` - Restore a deleted user

### Domains

- `GET /domains?include_deleted` - List domains
- `POST /domains` - Create domain (superuser)
- `GET /domains/{id}?include_deleted` - Get domain
- `PUT /domains/{id}` - Update domain (admin)
- `DELETE /domains/{id}?purge` - Delete domain (owner; soft), or purge an already-deleted one (superuser)
- `POST /domains/{id}/restore` - Restore a deleted domain (owner)

### Members

- `GET /domains/{id}/members` - List members (memberships of deleted users are omitted)
- `POST /domains/{id}/members` - Add member (admin; a deleted user is `404 User not found`)
- `PUT /domains/{id}/members/{uid}` - Change a member's role (admin)
- `DELETE /domains/{id}/members/{uid}` - Remove member (admin; this is a hard delete of the membership)

### Recipients

- `GET /domains/{id}/recipients?include_deleted` - List recipients
- `POST /domains/{id}/recipients` - Create recipient (admin)
- `GET /domains/{id}/recipients/{rid}?include_deleted` - Get recipient
- `PUT /domains/{id}/recipients/{rid}` - Update recipient (admin)
- `DELETE /domains/{id}/recipients/{rid}?purge` - Delete recipient (admin; soft), or purge an already-deleted one (superuser)
- `POST /domains/{id}/recipients/{rid}/restore` - Restore a deleted recipient (admin)

### Rules

- `GET /domains/{id}/rulesets` - List rulesets
- `POST /domains/{id}/rulesets` - Create ruleset
- `GET /domains/{id}/rulesets/{rsid}` - Get ruleset with its rules
- `PUT /domains/{id}/rulesets/{rsid}` - Update ruleset
- `DELETE /domains/{id}/rulesets/{rsid}` - Delete ruleset
- `POST /domains/{id}/rulesets/{rsid}/reorder` - Set the evaluation order of a ruleset's rules
- `POST /domains/{id}/rulesets/{rsid}/rules` - Create rule
- `PUT /domains/{id}/rules/{rule_id}` - Update rule
- `DELETE /domains/{id}/rules/{rule_id}` - Delete rule

Rulesets and rules have no soft delete of their own: deleting one is permanent. While
their domain is deleted they are unreachable (every route above answers `404 Domain not
found`) and they come back untouched when the domain is restored.

### Delivery Logs

- `GET /domains/{id}/delivery-log?include_deleted` - List delivery logs (`?status`, `?message_id`, `?limit`, `?offset`)
- `GET /delivery-log/{id}` - Get delivery log details
- `POST /delivery-log/{id}/retry` - Retry a `failed`, `exhausted` or `cancelled` delivery

The `status` filter and the `status` field use the vocabulary listed under
[Delivery statuses](webhooks.md#delivery-statuses).

!!! info "Interactive documentation"

    Full API documentation is available on a running server at `/docs` (Swagger UI) or `/redoc`.

## Deletion, restore and purge

!!! warning "Behaviour change in v0.5.0"

    `DELETE` on a user, API key, domain or recipient no longer removes the row. It
    **soft-deletes** it: the row is stamped with a `deleted_at` timestamp, disappears
    from every list and lookup, stops authenticating, receiving mail and delivering
    webhooks, and can be brought back with `POST .../restore`. Permanent removal is a
    separate, superuser-only step (`?purge=true`) that only works on a row that is
    already deleted.

    Delivery history is no longer severed by a delete: log rows keep their
    `domain_id` and `recipient_id`, and the history of a deleted domain stays readable
    to its owners and to superusers.

Users, API keys, domains and recipients carry a nullable `deleted_at` field in their
responses. It is `null` on a live row and you will only ever see it set on rows returned
with `?include_deleted=true`.

### What a delete does

`DELETE` returns `200` with the same message as before (`"Domain example.com deleted"`),
and the id answers `404` from then on, exactly as if the row were gone. The name is
released immediately: a new user, domain or recipient with the same name can be
created while the old one is deleted.

The delete cascades to what depends on the row, stamping the children with the same
timestamp as the parent:

| Deleting a... | Also... |
|---|---|
| **user** | deletes and **revokes** every API key the user still has. Memberships are kept, hidden while the user is deleted, and return with the user |
| **API key** | sets `is_active=false` as well; the key never authenticates again. A second `DELETE` answers `404 API key not found` |
| **domain** | deletes its recipients and **cancels** their pending and failed deliveries (`status=cancelled`, `last_error="Domain deleted"`). Rulesets, rules and members are kept, unreachable while the domain is deleted, and return with it |
| **recipient** | cancels its pending and failed deliveries (`last_error="Recipient deleted"`) |

A deleted row cannot be observed as live anywhere: a deleted API key or the key of a
deleted user gets `401`, mail for a deleted domain is refused with `550`, a deleted named
recipient falls through to the domain's catch-all or is refused, and the delivery worker
cancels rather than sends anything still addressed to a deleted recipient or domain.

### Reading deleted rows

Pass `?include_deleted=true` to include deleted rows in a list, or to fetch one by id.
The flag requires the role that may delete the resource:

| Route | Who may pass `include_deleted` |
|---|---|
| `GET /users`, `GET /users/{id}` | superuser (as for every user route) |
| `GET /auth/keys` | anyone, for their own keys. Also lists keys retired before v0.5.0, which have `is_active=false` and no `deleted_at` |
| `GET /domains` | superuser sees every deleted domain; a regular user sees deleted domains only where they are **owner** |
| `GET /domains/{id}` | owner or superuser |
| `GET /domains/{id}/recipients`, `GET .../recipients/{rid}` | admin or superuser while the domain is live. On a **deleted** domain the domain itself is resolved with the flag, so only its owners and superusers get through (the recipients of a deleted domain can be audited before restoring it); an admin gets `404` there |
| `GET /domains/{id}/delivery-log` | owner or superuser |

Without the flag a deleted id is `404` with the ordinary "not found" detail. With it,
the user routes check the superuser gate before looking anything up, so an insufficient
caller gets `403` whether or not the row exists. The domain-scoped routes resolve the
domain first: a **deleted** domain is `404` to everyone below owner, while a **live** one
is `403` below the required role.

`GET /delivery-log/{id}` needs no flag: a log whose domain is live is readable by any
member; one whose domain is deleted by its owners and superusers (`404` to anyone
else); one whose domain was purged (`domain_id` is `null`) by superusers only.

### Restore

- `POST /users/{id}/restore` - superuser
- `POST /domains/{id}/restore` - owner or superuser
- `POST /domains/{id}/recipients/{rid}/restore` - admin or superuser, and the domain must be live (`404` otherwise: restore the domain first)

Each returns `200` with the restored resource. Restoring a row that is not deleted answers
`409` (`"User is not deleted"`, `"Domain is not deleted"`, `"Recipient is not deleted"`).
If the name was re-taken by a live row in the meantime the restore answers `409` with the
same detail the create route uses - `"Username already exists"`,
`"Domain already exists"`, `"Recipient 'sales' already exists for this domain"` - so
delete or rename the new row first.

Restore brings back exactly what the delete took, and nothing more:

- **Users** come back with their memberships. **API keys are not restored** - revoking a
  credential is one-way. Create new keys.
- **Domains** come back with the recipients that were deleted *with* them (same
  timestamp). A recipient deleted on its own earlier keeps its own tombstone.
- **Deliveries** cancelled by the delete stay `cancelled`. `POST /delivery-log/{id}/retry`
  re-queues each one you want sent, and answers `409` while the domain or recipient is
  still deleted (`"Domain is deleted; restore it before retrying"`, `"Recipient is
  deleted; restore it before retrying"`).
- `is_enabled` / `is_active` are never changed by a delete or a restore.

### Purge

`DELETE ...?purge=true` on a user, domain or recipient removes the row permanently. It is
**superuser only** and only works on a row that is **already deleted**: on a live row it
answers `409` (`"User must be deleted before it can be purged"`, and likewise for domains
and recipients). Because deletion already cancelled every queued delivery, a purge can
never orphan a pending one.

Purge runs the pre-v0.5.0 cascade:

- a **user** takes their API keys and memberships with them;
- a **domain** takes its recipients, rulesets, rules and members with it;
- delivery-log rows are **kept**, with `domain_id` / `recipient_id` set to `null`. Those
  rows are then readable by superusers only.

API keys have no purge route: they go with their user's purge, or by retention.

### Retention

Nothing is purged automatically unless `FASTSMTP_SOFT_DELETE_RETENTION_DAYS` is set; by
default deleted rows are kept forever. With it set, the cleanup worker purges rows
deleted longer ago than that, and `fastsmtp purge-deleted` runs the same job by hand.
See [Retention](configuration.md#retention).
