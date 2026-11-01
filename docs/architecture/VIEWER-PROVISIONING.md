# M5 — guarded viewer preparation (disabled-account foundation)

This increment introduces **preparation only**, not a fully active viewer lifecycle.
Apply `infrastructure/postgres/007_viewer_authorization.sql` before enabling
these endpoints. Keycloak must expose the `oryva.provisioning.id` custom user
attribute to the management service account.

## Access and API

When Keycloak management configuration is complete:

- `POST /api/viewers/prepare` accepts
  `{"username":"viewer-one","email":"viewer@example.com"}`.
- `POST /api/viewers/provisioning/{id}/recover` inspects a previously reserved
  identity and conditionally advances it to `prepared`.

Both routes require a validated bearer token **and** successful authorization
as either `Oryva.ActiveMaster` or `Oryva.Admin`. Both policies check the
committed PostgreSQL active subject on every request. A `viewer` role cannot
manage viewers. Only the master may manage administrator accounts.

## Failure and recovery

The database reserves a unique username and case-insensitive email before
contacting Keycloak. Conflicting reservations return HTTP 409. The service
creates a disabled, email-unverified Keycloak user carrying the exact reservation
UUID as the ownership marker. It rereads the canonical identity and requires
matching username, email, ownership marker, disabled status, no password
credential, and **zero direct or effective ORYVA realm roles**.

Only then can the SQL row move from `reserved` to `prepared`, bound to the
verified Keycloak subject. `prepared` is **not active**; viewer API access
requires a separate `active` row and exclusive validated viewer realm role.

A lost or ambiguous Keycloak response leaves the reservation intact. Recovery
does **not** create a user or adopt an unmarked user; missing or mismatched
identities are rejected. Concurrent prepared transitions are guarded by
conditional SQL. The reservation ID can be found through privileged database
operations if the original request failed before returning it; a future
operational lookup API should improve this recovery experience.

## Explicitly out of scope

No viewer realm role assignment, credential enrollment, email verification,
activation, revocation, invitation or production account enablement is added.
Before production, implement cross-instance locks for privileged transitions,
durable audit events, stable error contracts for external Keycloak failures,
rate limiting, operational recovery, and HTTP authorization/security E2E tests.

The real Keycloak/PostgreSQL E2E suite verifies reservation contention,
case-insensitive duplicate rejection, canonical disabled identity, no roles or
password, idempotent recovery, missing identity rejection and ownership-marker
mismatch. Production Keycloak service-account permissions require a separate
least-privilege review.
