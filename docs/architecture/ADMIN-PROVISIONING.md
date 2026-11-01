# M4 admin provisioning — disabled-account foundation

The API exposes `POST /api/master/admins/prepare` **only** when a complete, validated Keycloak management client configuration exists. The endpoint requires `Oryva.ActiveMaster`, which verifies both the validated master JWT realm role and the active PostgreSQL master subject on each request.

Request JSON: `{"username":"new-admin","email":"admin@example.com"}`.

The endpoint creates a **disabled, uncredentialed Keycloak identity only**. It does not grant the admin role, enable the account, send an invitation, or claim that an admin was fully created. Keycloak username conflicts fail; idempotent retry/reconciliation is not yet implemented. The management client rejects redirects and does not use cookies.

Required configuration (secrets must come from a secret manager):
- `ORYVA_KEYCLOAK_MANAGEMENT_URL` — Keycloak base URL (HTTPS, except loopback for local development)
- `ORYVA_KEYCLOAK_MANAGEMENT_CLIENT_ID` — dedicated management service client
- `ORYVA_KEYCLOAK_MANAGEMENT_CLIENT_SECRET` — dedicated client secret

This is **not** a complete production admin workflow. Before release, add input normalization and uniqueness rules, reconciliation, per-user ownership metadata, least-privilege management permissions, secure invitation/credential setup, exclusive admin-role assignment, activation, revocation, audit logging, rate limits, and end-to-end HTTP tests. Do not use the bootstrap service account as a general-purpose production management account.

## PostgreSQL reservation increment (M4)

Apply `infrastructure/postgres/002_admin_provisioning.sql` through the deployment migration process before exposing the endpoint. The API now reserves the intended username and email in PostgreSQL before calling Keycloak. Duplicate username or case-insensitive email reservations fail closed. A returned `provisioningId` identifies the attempt.

The current Keycloak adapter creates a disabled account **without** an ownership marker or verified subject ID. Accordingly the reservation is deliberately marked `reconciliation_required` even after successful creation; it cannot be treated as proof of Keycloak ownership. A later coordinator must write a Keycloak ownership marker, retrieve and verify the subject, and transition to `prepared` before any role assignment.

The API currently propagates errors on duplicate reservation and Keycloak failures; improve these to stable problem responses in a later increment. No admin role assignment or activation is exposed.

## Canonical subject binding increment

After creating a disabled user, the API fetches the exact username from Keycloak, rereads its canonical user representation, confirms the same subject and disabled state, and binds that subject to the original PostgreSQL reservation. The reservation remains `reconciliation_required`: subject binding is **not** proof of ownership or authorization to promote. Next, introduce a dedicated provisioning ownership marker (separate from the sole-master bootstrap marker), verify it along with email and role state, and add integration tests before any role assignment or enablement.

## Ownership-marker increment

Disabled admin candidates are created with the `oryva.provisioning.id` custom Keycloak attribute set to the PostgreSQL reservation UUID. After Keycloak creation, the API fetches canonical user detail and requires the exact single marker to match before binding the subject. Keycloak must permit service-account read/write access to this attribute through its effective user profile; the isolated E2E setup configures it.

The state remains `reconciliation_required` intentionally. Still required: canonical email matching, verifying absence of conflicting roles, an atomic transition to `prepared`, safe retry/recovery, audit events and account lifecycle tests. No role assignment or activation is implemented.

## Prepared-state verification increment

The preparation endpoint now requires canonical Keycloak username, disabled status, exact reservation ownership marker, case-insensitive canonical email match and zero direct ORYVA realm roles before binding the subject and transitioning the PostgreSQL reservation to `prepared`. The transition is conditional on the reserved subject and reconciliation state. This is **not** role assignment or activation.

Still required: handle concurrent external Keycloak mutations, ensure no effective/composite ORYVA roles, recover ambiguous creation failures, audit state transitions, add E2E coverage, and implement a guarded role assignment/activation coordinator.

## Effective-role guard

Before marking an admin candidate prepared, the API now checks both direct realm role mappings and Keycloak's composite/effective realm role mapping endpoint. Any effective `master`, `admin`, or `viewer` role fails closed, including roles inherited from composite mappings. The checks are point-in-time and do not protect against concurrent external Keycloak mutation. Activation must repeat identity, ownership and role checks immediately before changes.

## Read-only reconciliation endpoint

`GET /api/master/admins/provisioning/{id}` requires `Oryva.ActiveMaster` and configured Keycloak management credentials. It reports persisted state and whether the current Keycloak identity matches the reservation's username, email, disabled state, ownership marker, bound subject and absence of direct/effective ORYVA roles. Findings include `identity_missing`, `identity_mismatch`, `unexpected_role`, and `verified_disabled_candidate`. Unknown reservation IDs return 404. The endpoint **does not** change state, create users, assign roles, or enable accounts.

A verified inspection is point-in-time, not an activation permit. A future mutating recovery coordinator must serialize per reservation, revalidate all preconditions, and safely handle ambiguous external responses.

## Explicit recovery of interrupted preparation

`POST /api/master/admins/provisioning/{id}/recover` requires the active-master policy. For `reconciliation_required` reservations, it rechecks the existing disabled Keycloak account, ownership marker, email, subject binding and direct/effective ORYVA role absence, then conditionally binds the subject and marks the reservation `prepared`. It never creates, enables, adopts unmarked identities or assigns roles. Missing reservations return 404; unverified candidates return 409. Prepared reservations are inspected without mutation.

Recovery is not a substitute for serialization across independent Keycloak writes. Before admin activation, introduce per-reservation locking and repeat checks at the activation boundary.

## Cross-instance recovery serialization

The recovery endpoint acquires a session-scoped PostgreSQL advisory lock derived from the reservation UUID (a stable SHA-256-based, namespaced 32-bit key) **before** reading the reservation. Only one ORYVA recovery coordinator can advance the same reservation at a time across API instances using the same PostgreSQL database. Different reservations can progress independently; a rare hash collision merely serializes unrelated reservations.

The lease remains open across Keycloak reads and PostgreSQL transitions, and the coordinator checks that the session still holds it before binding the subject and marking the reservation prepared. A concurrent recovery returns HTTP 409 without mutating the reservation. The lease explicitly unlocks before returning its connection to the pool. The PostgreSQL/Keycloak integration test verifies cross-session exclusion, no mutation under contention, independent reservation locks and release/reacquisition.

**Important boundary:** PostgreSQL advisory locks coordinate ORYVA callers only. They do not fence an external Keycloak administrator, a lost network response, or a different system modifying Keycloak. An activation coordinator must recheck Keycloak immediately before each privilege-changing operation, use its own recovery state machine and fail closed on ambiguity. No admin role assignment, enablement or invitation is introduced by this increment.

## Durable, append-only transition audit (pending CI)

Apply `infrastructure/postgres/003_admin_provisioning_audit.sql` after migration 002, **before** enabling admin provisioning APIs. Every successful PostgreSQL reservation/state transition now writes its audit event in the same SQL statement: `reserved`, `reconciliation_required`, `subject_bound` and `prepared`. If the audit insert fails, the state change rolls back. Events store only reservation UUID, event type, original actor subject, server-side timestamp and monotonic event ID; they never contain passwords, bearer tokens, email addresses or raw Keycloak responses.

The table rejects UPDATE, DELETE and TRUNCATE through PostgreSQL triggers (database superusers and privileged operators can still bypass ordinary database controls). `GET /api/master/admins/provisioning/{id}/events` exposes the ordered history to the active master only. Unknown IDs return 404.

**Scope limit:** this records committed PostgreSQL transitions, not every denied attempt or external Keycloak write. Keycloak requests may fail before a transition is recorded. Before privileged admin activation, add explicit audit events for attempted grants, denied actions, ambiguous remote results, credential setup, enablement and revocation. Retention, access monitoring, backups and production database role privileges still require operational policy.
