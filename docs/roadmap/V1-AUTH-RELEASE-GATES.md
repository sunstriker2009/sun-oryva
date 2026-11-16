# OUTPOST v1 authentication release gates

This is a **blocking release contract**, not evidence of production readiness. The OIDC routes exist behind explicit server-side configuration; do not enable them for production users until the remaining gates pass.

## Verified implementation inventory (not release approval)

- Next.js routes: `GET /api/auth/login`, `GET /auth/callback`, and `POST /api/auth/logout`.
- PostgreSQL-backed one-time OIDC transactions and opaque server-side sessions; `__Host-oryva-session` cookie; server-side logout revocation with exact origin/path checks.
- **Blocking:** `resolveServerAuthorization()` in `src/frontend/apps/console/lib/auth-boundary.ts` still returns `unavailable`. This intentionally denies protected console access until trusted backend role and active-status resolution is integrated.
- **Blocking:** Live Keycloak browser OIDC E2E and deployment hardening evidence are outstanding. Existing Keycloak provisioning/bootstrap CI is not browser-login validation.

## Route integration
- [x] Implement server-configured login GET, callback GET and logout POST routes.
- [ ] Verify trusted public origin/proxy configuration in deployment; never trust arbitrary Host or X-Forwarded-* headers.
- [ ] Prove state, nonce, PKCE S256, exact redirect URI, browser binding, atomic transaction consumption, replay rejection and provider error handling against live Keycloak.
- [ ] Prove ID-token signature, issuer, audience, nonce, expiry, allowed algorithm and key rotation against live Keycloak.
- [ ] Browser-verify Secure HttpOnly SameSite host-only cookies, expiry, no-store responses and fixation/rotation protection.
- [ ] Browser-verify same-origin POST logout, revocation before cookie expiration, and fail-closed database errors.

## Trusted authorization
- [ ] Resolve effective Master/Admin/Viewer role and current active account status from trusted backend data on **each privileged request**; bind backend subject to verified session issuer/subject. Never authorize from browser-supplied roles or identity-token role claims.
- [ ] Deny unknown/ambiguous roles, inactive/deleted accounts, malformed subjects and backend outages; test immediate role changes and revocation.
- [ ] Replace fail-closed `resolveServerAuthorization()` only after negative integration tests.

## Test and deployment evidence
- [ ] Keycloak + PostgreSQL browser E2E: login, callback, session, logout and re-login.
- [ ] Negative E2E: state/nonce/PKCE mismatch, replay, expiry, duplicate parameters, invalid signature/audience/issuer, CSRF, cross-origin logout, inactive user and backend outage.
- [ ] Validate TLS, secret rotation, proxy settings, migrations, cleanup/retention, rate limiting, safe observability and rollback.
- [ ] Required CI green on exact release commit; document production smoke test and operator recovery.

**Release decision:** No v1 readiness claim until the remaining gates have documented evidence. Keep feature branches, squash PRs and branch protections.
