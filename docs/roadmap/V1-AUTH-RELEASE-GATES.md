# ORYVA v1 authentication release gates

This checklist is a **blocking release contract**, not evidence that the console login flow is live. Keep public OIDC login/callback/logout routes disabled until every applicable gate passes.

## Route integration
- [ ] Register Next.js login GET, callback GET and logout POST handlers, backed by the existing server-only orchestration modules; reject all other methods.
- [ ] Require explicit enabled configuration and exact trusted public origin; never infer a security decision from untrusted Host or X-Forwarded-* headers.
- [ ] Validate OIDC discovery and authorization endpoint, state, nonce, PKCE S256, exact redirect URI and browser binding. Consume transactions atomically once; reject replay and provider errors.
- [ ] Verify ID token with a maintained JOSE/OIDC verifier: issuer, audience, signature, allowed algorithm, nonce, expiry, and key rotation. Never create a session from unverified claims.
- [ ] Issue only opaque host-only Secure HttpOnly SameSite cookies with server-side expiration, session rotation and non-cacheable responses; never expose tokens to browser JavaScript.
- [ ] Enforce POST + same-origin/CSRF checks on logout, revoke PostgreSQL session before clearing cookies, and fail closed on revocation errors.

## Trusted authorization
- [ ] Resolve effective Master/Admin/Viewer role and active account status from trusted backend data on each privileged request, not from browser-supplied role or stale identity claims.
- [ ] Deny unknown roles, inactive/deleted accounts, backend failures and malformed subjects. Verify role transitions and revocation take effect without relying on cookie expiry.

## Test and deployment evidence
- [ ] Keycloak + PostgreSQL browser E2E: successful login, callback, session, logout and re-login.
- [ ] Negative E2E: state/nonce/PKCE mismatch, replay, expired transaction, duplicate parameters, invalid signature/audience/issuer, CSRF and cross-origin logout, inactive user, backend outage.
- [ ] Validate TLS, secret rotation, proxy/origin settings, database migrations, retention/cleanup, rate limiting, observability without secret leakage and rollback procedure.
- [ ] Required backend/frontend CI green on the exact release commit; document manual production smoke test and operator recovery.

**Release decision:** No v1 authentication readiness claim until the above gates have documented evidence. Passing isolated unit tests is not a substitute for live Keycloak browser E2E. Keep feature branches, squash PRs and branch protections enforced.
