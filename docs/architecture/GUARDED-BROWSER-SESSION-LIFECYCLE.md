# Guarded browser session lifecycle orchestration (internal only)

The opt-in `OryvaGuardedBrowserSessionLifecycle` bridges the existing same-origin, CSRF-validated cookie boundary to PostgreSQL-backed `ViewerInvitationBrowserExchangeStore.RotateAsync` and `RevokeAsync`.

- No production endpoint is registered; no public enrollment, credential mutation, email verification or account activation is enabled.
- The guarded POST marker is mandatory. Cookie bearer extraction is untrusted until the store transaction verifies its digest and viewer/challenge/Keycloak subject snapshot.
- Rotation commits PostgreSQL first, then issues a replacement `__Host-oryva-browser` cookie with the **original** database expiry. The old bearer cannot be reused.
- Revocation commits PostgreSQL first, then clears browser and CSRF cookies. Clearing a cookie never substitutes for revocation.
- On cookie-write failure after a committed rotation, the operation fails closed; the old bearer is already invalid. Never return the replacement secret in JSON or logs.
- The viewer ID is only a database lookup key, not proof of identity or an activation grant.

## Validation status

The isolated `tests/unit/Sun.Security.GuardedSession.PolicyTests` exercises TestServer POSTs with origin/CSRF rejection and missing, malformed or duplicate browser bearers, requiring denial before opening a database connection. The suite is registered in the main CI workflow. The new `tests/integration/Sun.Security.GuardedSession.E2E` suite is registered in the full-stack workflow and exercises real PostgreSQL/TestServer rotation, stale-bearer replay denial, revocation, cookie attributes, origin/CSRF/duplicate-cookie rejection, and unchanged viewer state. **These new tests have been committed but have not yet been observed passing on the latest PR head.** The existing database-only invitation exchange E2E covers 16-way rotation/revocation concurrency and expiry; end-to-end HTTP concurrency (16 contenders, exactly one winner) has been added but needs current-head CI verification; response-header failures and independent Keycloak email/credential verification remain outstanding. The class is intentionally not wired to a public API until those checks and independent Keycloak email ownership/credential enrollment review pass.

This internal milestone must not be interpreted as backend v1 completion or permission to activate unverified accounts.

## Cross-viewer regression gate (follow-up)

The PostgreSQL/TestServer suite now also sends valid same-origin, CSRF-protected
requests carrying a live viewer A bearer to rotation and revocation handlers
targeting an unrelated viewer ID. Both operations must return HTTP 403 without
a Set-Cookie header, and viewer A's original bearer must remain live. The
target viewer ID is intentionally not treated as proof of identity.

These assertions are source changes only until the exact PR-head CI run is
observed passing. No public route, Keycloak mutation or account activation is
introduced. Remaining release gates include response-header failure handling,
independent email ownership proof, disabled-account credential enrollment,
password recovery, production SMTP/proxy review and full lifecycle E2E.
