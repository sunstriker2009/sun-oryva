# Guarded browser session lifecycle orchestration (internal only)

The opt-in `OryvaGuardedBrowserSessionLifecycle` bridges the existing same-origin, CSRF-validated cookie boundary to PostgreSQL-backed `ViewerInvitationBrowserExchangeStore.RotateAsync` and `RevokeAsync`.

- No production endpoint is registered; no public enrollment, credential mutation, email verification or account activation is enabled.
- The guarded POST marker is mandatory. Cookie bearer extraction is untrusted until the store transaction verifies its digest and viewer/challenge/Keycloak subject snapshot.
- Rotation commits PostgreSQL first, then issues a replacement `__Host-oryva-browser` cookie with the **original** database expiry. The old bearer cannot be reused.
- Revocation commits PostgreSQL first, then clears browser and CSRF cookies. Clearing a cookie never substitutes for revocation.
- On cookie-write failure after a committed rotation, the operation fails closed; the old bearer is already invalid. Never return the replacement secret in JSON or logs.
- The viewer ID is only a database lookup key, not proof of identity or an activation grant.

## Validation status

The isolated `tests/unit/Sun.Security.GuardedSession.PolicyTests` exercises TestServer POSTs with origin/CSRF rejection and missing, malformed or duplicate browser bearers, requiring denial before opening a database connection. The suite is registered in the main CI workflow. **Not yet verified:** PostgreSQL/TestServer success paths, concurrent rotation, stale-bearer replay, expiry, response-header failures and actual CI execution. The class is intentionally not wired to a public API until those checks and independent Keycloak email ownership/credential enrollment review pass.

This internal milestone must not be interpreted as backend v1 completion or permission to activate unverified accounts.
