# M5 — guarded viewer preparation, role assignment, activation and deactivation

This increment introduces preparation, **guarded role assignment**, read-only activation readiness and a guarded activation transition. Credential enrollment and the full account lifecycle are not yet implemented.
Apply `infrastructure/postgres/007_viewer_authorization.sql` and then
`infrastructure/postgres/008_viewer_role_assignment.sql` and then
`infrastructure/postgres/009_viewer_activation.sql` and then
`infrastructure/postgres/010_viewer_deactivation.sql` before enabling
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

## Reservation audit (migration 011)

Apply `infrastructure/postgres/011_viewer_reservation_audit.sql` **after**
`010_viewer_deactivation.sql` and before deploying the updated API.
Every new viewer reservation and its `reserved` event are committed by
**one PostgreSQL statement**. The event records the authenticated requesting
master/admin subject and role, not an email, password or bearer token.
A uniqueness conflict inserts neither a new account nor an audit event;
if audit insertion fails, the reservation insert rolls back as well.

The existing append-only UPDATE/DELETE/TRUNCATE triggers protect the new
event type. Older reservations are **not** backfilled with invented actor
attribution; their prior audit history remains unchanged. Subsequent
role/activation/revocation events retain their existing audit semantics.
This does not yet audit the `prepared` transition or every failed external
Keycloak operation. Those gaps and credential enrollment remain outstanding.

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

## Guarded activation and recovery

`POST /api/viewers/provisioning/{id}/activate` requires an authenticated
**database-active master or admin**, an exclusive corresponding realm role,
and exactly one token subject. Viewers, inactive admins and role-only JWTs
cannot invoke it. The authenticated actor subject and role are written to the
append-only PostgreSQL audit trail for each activation transition.

Under the same cross-instance advisory lease as preparation and role assignment,
the coordinator accepts only `role_assigned`, `activation_pending` or `active`.
For `role_assigned`, it rechecks **all** preflight gates against canonical
Keycloak state: exact subject, username, email and ownership marker; disabled
identity; exclusive direct/effective viewer roles; password credential;
verified email; and an explicitly empty required-actions list. It then commits
`activation_pending` and its actor audit **before** any Keycloak enablement.

`activation_pending` is never accepted by the viewer authorization query.
If a Keycloak enablement response is lost, an explicit retry under the lease
re-reads Keycloak and accepts the enabled identity **only** with that durable
pending intent and complete ownership/role/credential verification. If still
disabled, it rechecks the gates before sending enablement and re-reads the
identity afterward. Only then can a conditional SQL transition commit
`active` and its audit event atomically. The active state is verified again
on an idempotent retry; drift fails closed. An externally enabled candidate
without a prior activation intent is **not** adopted.

The API returns 404 for an unknown ID, 409 for contention, invalid state or
failed verification, and 200 with `provisioningId`, `state`, and
`transitioned` for successful activation or verified idempotence. Ambiguous
Keycloak failures can leave a durable `activation_pending` state requiring
an explicit retry; no account is silently activated. This API never creates
credentials, verifies email, sends invitations or bypasses required actions.

Migration `009` extends the constrained viewer states and audit event types.
It must be applied **after** `008` and before enabling the route. Advisory
locking does not fence privileged out-of-band Keycloak writers; production
service-account permissions and monitoring remain essential.

The full-stack CI suite exercises test-only verified viewer enablement,
uncredentialed rejection, cross-instance lock contention, subject-bound
conditional transitions, idempotence, actor audit, ambiguous enablement
reconciliation and rejection of externally enabled accounts. Test fixtures
use ephemeral Keycloak/PostgreSQL instances and do not activate production
accounts.

## Database-first viewer deactivation and recovery

`POST /api/viewers/provisioning/{id}/deactivate` requires a validated
database-active master or admin with an exclusive corresponding realm role and
exactly one token subject. A viewer or inactive admin cannot manage viewers.
The coordinator uses the same cross-instance viewer provisioning advisory lease.

Only `active`, `deactivation_pending` and `deactivated` reservations with
a bound subject are eligible. For an active reservation, the coordinator
**commits `deactivation_pending` and its actor-attributed audit before any
Keycloak I/O**. PostgreSQL viewer authorization accepts only `active`, so
previously issued access JWTs immediately lose authorization even if Keycloak
is unreachable. The coordinator then verifies exact subject, username, email
and the single `oryva.provisioning.id` ownership marker, disables the user,
rereads disabled status, logs out sessions and rereads again. Only then does
it atomically commit `deactivated` and the completion audit.

A lost disable/logout response leaves durable pending intent for explicit
retry under the same lease. A deactivated retry verifies ownership, disabled
status and logout before returning idempotently. Role drift must not prevent
revoking a verified owned account. Ownership mismatch never authorizes
disabling an unrelated Keycloak user. `activation_pending` is intentionally
not eligible for this operation: it requires guarded activation reconciliation
first. Network failures may return 5xx while PostgreSQL remains safely
revoked and pending. Operators should retry only after investigating the
provider's canonical identity and state.

Migration `010` extends constrained states and append-only actor audit.
Unknown IDs return 404; lock contention or invalid states return 409.
No passwords, tokens or production identities are created or changed by CI.
The Keycloak logout call revokes sessions and refresh tokens; PostgreSQL
authorization is the protection for previously issued stateless JWTs.

## Explicitly out of scope

No production credential enrollment, email verification, invitation or
production account enablement is added. Viewer deactivation is limited to
already active, owned identities; broader recovery tooling remains outstanding. Guarded activation
requires previously completed external enrollment and verification.
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
