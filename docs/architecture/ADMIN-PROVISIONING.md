# M4 admin provisioning — disabled-account foundation

The API exposes `POST /api/master/admins/prepare` **only** when a complete, validated Keycloak management client configuration exists. The endpoint requires `Oryva.ActiveMaster`, which verifies both the validated master JWT realm role and the active PostgreSQL master subject on each request.

Request JSON: `{"username":"new-admin","email":"admin@example.com"}`.

The endpoint creates a **disabled, uncredentialed Keycloak identity only**. It does not grant the admin role, enable the account, send an invitation, or claim that an admin was fully created. Keycloak username conflicts fail; idempotent retry/reconciliation is not yet implemented. The management client rejects redirects and does not use cookies.

Required configuration (secrets must come from a secret manager):
- `ORYVA_KEYCLOAK_MANAGEMENT_URL` — Keycloak base URL (HTTPS, except loopback for local development)
- `ORYVA_KEYCLOAK_MANAGEMENT_CLIENT_ID` — dedicated management service client
- `ORYVA_KEYCLOAK_MANAGEMENT_CLIENT_SECRET` — dedicated client secret

This is **not** a complete production admin workflow. Before release, add input normalization and uniqueness rules, reconciliation, per-user ownership metadata, least-privilege management permissions, secure invitation/credential setup, exclusive admin-role assignment, activation, revocation, audit logging, rate limits, and end-to-end HTTP tests. Do not use the bootstrap service account as a general-purpose production management account.
