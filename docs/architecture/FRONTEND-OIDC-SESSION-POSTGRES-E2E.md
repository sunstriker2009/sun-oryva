# Console session PostgreSQL integration coverage

The existing frontend CI PostgreSQL 17 service runs `oidc-session-postgres.e2e.test.mjs` alongside the OIDC transaction integration suite.

The test creates an isolated schema, applies the proposed session migration twice, issues a session, confirms only a hash is persisted, resolves the identity across eight independent PostgreSQL connections, races eight revocations and requires exactly one winner, confirms revoked sessions fail on all connections, tests absolute expiry, and checks that other sessions remain usable.

Local execution requires an isolated test database and `ORYVA_OIDC_TEST_DATABASE_URL`; without the variable the test is explicitly skipped. CI already supplies this variable. No production database should be used.

This does **not** enable login routes or replace the fail-closed authorization resolver. Before production use, complete trusted backend active-role validation, CSRF and logout handling, callback orchestration, migration deployment and real Keycloak E2E.
