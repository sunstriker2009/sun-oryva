# ADR-004 — ORYVA Realm Provisioning (Development)

**Status:** Accepted for local development only.

Use a versioned, non-secret JSON Keycloak realm import to initialize the `oryva` realm on first startup. Roles are declared but no application users or OIDC clients are pre-seeded. Import is deterministic for an empty development database and must not be mistaken for a migration mechanism.

Production realm changes require an explicit provisioning/migration workflow and integration tests. The single-master invariant belongs to ORYVA's management layer; Keycloak's role model alone cannot enforce cardinality or prevent unauthorized role assignment.

This ADR does not approve browser token storage, password policy, admin client credentials, or production Keycloak deployment.
