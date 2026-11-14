# OIDC console server-side session boundary

This component creates cryptographically random, opaque 256-bit session handles. Only SHA-256 hashes are stored in PostgreSQL; browser cookies are `__Host-oryva-session`, Secure, HttpOnly, host-only, Path=/, SameSite=Lax, with a 30-minute absolute lifetime. Sessions can be revoked server-side, including across replicas.

**Identity is not authorization.** Resolving a session returns only issuer and subject, never a role. The caller must query the trusted ORYVA backend for current active status and effective role on every privileged request. The existing fail-closed `resolveServerAuthorization` remains unchanged.

**Not yet production-ready:** This is a proposed database migration and isolated module, not wired to a route. Complete OIDC callback orchestration, trusted origin checks, CSRF defenses for state-changing requests, logout/revocation, database integration tests, session fixation tests, backend active-role integration and operational retention are still required. Cookie Max-Age must not exceed database expiry.
