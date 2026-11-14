# OIDC logout revocation boundary

The server-only logout orchestrator accepts **POST** with an Origin exactly matching the configured console origin. It never trusts the inbound Host header as the origin of truth. With a valid opaque session cookie, it awaits PostgreSQL revocation before returning a no-store redirect that expires both the session and OIDC binding cookies.

Missing or ambiguous session credentials are cleared without a database mutation. A database revocation error fails closed rather than presenting a misleading success redirect. The revocation store is idempotent for already revoked sessions.

**Remaining integration gates:** expose only a POST Next.js logout handler, use the trusted server-side runtime configuration for `expectedOrigin`, ensure forms submit same-origin, wire the PostgreSQL store and error response, and run browser/Keycloak E2E. Never use GET for state-changing logout.
