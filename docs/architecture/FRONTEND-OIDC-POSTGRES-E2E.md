# OIDC transaction PostgreSQL integration tests

The frontend CI job now provisions an ephemeral PostgreSQL 17 service and sets `ORYVA_OIDC_TEST_DATABASE_URL` for the Node test suite.

The E2E test creates a unique temporary schema, applies the proposed migration twice to verify idempotence, tests duplicate issue and incorrect browser binding, races 32 consume requests across eight independent PostgreSQL connections, asserts exactly one winner, decrypts its payload, verifies replay rejection and expiry, then drops the schema.

The test runs only when `ORYVA_OIDC_TEST_DATABASE_URL` is configured; otherwise it is explicitly skipped. The CI job always configures it. **Do not use a production database URL.** Test credentials are ephemeral and non-production.

This verifies storage concurrency, not a complete OIDC login. Remaining: deployment migration management, browser cookie binding, vetted token verification, session lifecycle and Keycloak browser E2E.
