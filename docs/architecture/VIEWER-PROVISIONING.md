# M5 — guarded viewer preparation and disabled realm-role assignment

This increment introduces preparation and **guarded role assignment**, not a fully active viewer lifecycle.
Apply `infrastructure/postgres/007_viewer_authorization.sql` and then
`infrastructure/postgres/008_viewer_role_assignment.sql` before enabling
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

A lost or ambiguous Keycloak response returns HTTP 409 with the durable
`provisioningId` and leaves the reservation intact. Recovery
does **not** create a user or adopt an unmarked user; missing or mismatched
identities are rejected. Concurrent prepared transitions are guarded by
conditional SQL. The reservation ID is returned in the conflict response when the request
remains connected; otherwise privileged database inspection can locate it.
A future operational lookup API should improve this recovery experience.

## Guarded role assignment

`POST /api/viewers/provisioning/{id}/assign-viewer-role` requires the same
active-master/active-admin authorization as viewer preparation, with a single
validated token subject and exclusive ORYVA role. It takes a cross-instance
PostgreSQL advisory lease and verifies the exact reservation subject,
ownership marker, username, email, disabled and unverified-email status,
absence of password credentials, and zero or exclusively `viewer` direct
**and effective** ORYVA realm roles. Any `master` or `admin` role fails closed.

A `prepared` reservation must have zero roles. The coordinator commits
`role_assignment_pending` and its actor-bound audit event before contacting
Keycloak. It assigns only the `viewer` realm role, then re-reads Keycloak and
commits `role_assigned` with a second audit event only after verification.
A lost response leaves durable intent for explicit retry. `role_assigned`
is still disabled and does not authorize viewer API access. A repeat on
`role_assigned` verifies Keycloak and returns an idempotent result.

`GET /api/viewers/provisioning/{id}/audit` returns the append-only,
transactional role-assignment audit history to active master/admin callers.
The database rejects UPDATE, DELETE and TRUNCATE of the audit table. These
records contain no credentials or tokens. Advisory locking coordinates ORYVA
writers, but does not fence external Keycloak administrators; production
permissions must restrict competing privileged writers.

## Viewer activation readiness (read-only)

`GET /api/viewers/provisioning/{id}/activation-readiness` is available only
with complete Keycloak management configuration and a validated **active master
or PostgreSQL-active admin** token. A viewer cannot inspect readiness. The
endpoint returns HTTP 404 for an unknown reservation and HTTP 409 if a
provisioning operation holds the cross-instance advisory lease.

Under the same lease used for viewer preparation and role assignment, it checks:

1. The persisted viewer reservation is exactly `role_assigned` and has a bound subject.
2. Keycloak resolves the exact username, subject, email and single
   `oryva.provisioning.id` ownership marker, and the user is still **disabled**.
3. Direct **and effective** ORYVA realm roles are each exclusively `viewer`;
   an inherited `admin` or `master` role rejects readiness.
4. A password credential exists, email is verified and the required-actions
   collection is present and empty.

The JSON response includes `provisioningId`, `state`, `ready`, and a
non-sensitive `finding` such as `role_not_assigned`, `identity_mismatch`,
`role_mismatch`, `password_missing`, `email_not_verified`,
`required_actions_pending`, or `ready_for_guarded_activation`.

This preflight **does not** create credentials, mark emails verified, change
database state, enable Keycloak users, or authorize viewer APIs. Readiness
is point-in-time; any later activation coordinator must reacquire the lease
and repeat every verification immediately before a durable activation intent.
Advisory locks coordinate ORYVA instances but cannot fence an external
Keycloak administrator, so least-privilege Keycloak administration is required.

The CI integration suite uses isolated test-only credentials to demonstrate
a positive readiness result without enabling the account. Production
credential enrollment and verification remain separate, unfinished flows.

## Explicitly out of scope

No credential enrollment, email verification, activation, revocation,
invitation or production account enablement is added.
Before production, extend durable audit coverage to preparation and lifecycle transitions,
stable error contracts for external Keycloak failures,
rate limiting and operational recovery. HTTP authorization E2E covers the active-admin and role-conflict branches; active-master management E2E remains outstanding.

The real Keycloak/PostgreSQL E2E suite verifies guarded viewer role assignment,
role exclusivity, cross-instance lock contention, lost-response recovery,
append-only audit, reservation contention,
case-insensitive duplicate rejection, canonical disabled identity, no roles or
password, idempotent recovery, missing identity rejection and ownership-marker
mismatch. Production Keycloak service-account permissions require a separate
least-privilege review.
