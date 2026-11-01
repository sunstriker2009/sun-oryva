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
