# Internal invitation-to-browser exchange (migration 020)

**Status:** internal backend foundation only; not a public endpoint or a completed enrollment flow. Apply `infrastructure/postgres/020_viewer_invitation_browser_exchange.sql` after migration 019, then `021_viewer_invitation_exchange_quotas.sql`, before running the updated invitation exchange code.

## Contract

A 256-bit invitation bearer secret can be exchanged **once**, while it is still valid, for a different 256-bit, five-minute browser secret. The PostgreSQL transaction locks the viewer before updating the challenge, records the existing append-only `consumed` audit event, stores only the SHA-256 digest of the new secret, and cancels pending/leased SMTP deliveries. A failed insert or audit rolls everything back. Cross-replica races have one winner.

Both issuance and exchange enforce a subject-bound, `role_assigned` viewer and unchanged recipient email. Reissuing an invitation revokes any outstanding browser exchanges under the viewer lock. A PostgreSQL trigger also permanently revokes browser exchanges when the viewer's email, Keycloak subject or lifecycle state changes, **including when changed back**. Expiry is enforced against PostgreSQL time.

The returned `ViewerInvitationBrowserExchange` intentionally redacts the secret from JSON and `ToString()`. No secret or plaintext email is written to the browser session table. The internal `IsLiveAsync` method is **point-in-time inspection only** and MUST NOT be used as authentication, a password-write permission or an activation gate.

## Cross-replica exchange attempt quota (migration 021)

The internal exchange now charges a PostgreSQL-backed, viewer-scoped, fixed 60-second window **before inspecting the invitation token**, including malformed and incorrect tokens. A row-level conflict update serializes concurrent attempts across API replicas. At most **32 attempts** are allowed per viewer per window; count 33 is the saturated sentinel, and repeated denials do not grow the counter. Failed or throttled exchanges return the same generic null result, with no token, email, source IP or Keycloak subject persisted in the quota row. Denied exchanges commit the quota charge without consuming the invitation; successful exchanges commit quota, invitation consumption and audit in the same transaction. Internal database errors fail closed.

This is **not a complete public endpoint abuse defense**. A caller who knows a viewer ID can temporarily exhaust that viewer's quota. Before any public browser route, add separately reviewed distributed source-IP and global admission limits with trusted reverse-proxy configuration, generic HTTP responses, monitoring and abuse recovery. Never accept untrusted `X-Forwarded-For` as an identity key. The quota is not email verification, a session, a password-write grant or permission to enable Keycloak accounts.

## Opt-in browser POST request guard (PR #102 verified)

`OryvaBrowserRequestGuard` in `Sun.Security.AspNetCore` is a reusable, **unregistered** middleware boundary for future explicitly marked POST endpoints. It rejects non-HTTPS requests, unexpected Host or Origin, missing/duplicate Origin, supplied non-`same-origin` Fetch Metadata, and absent/mismatched/malformed 256-bit-shaped CSRF double-submit tokens. It requires a single `__Host-oryva-csrf` cookie and matching `X-Oryva-Csrf` header with constant-time comparison, rejects duplicate CSRF cookies, and sets no-store/no-referrer response headers. The expected canonical HTTPS origin is validated at startup; raw `X-Forwarded-*` headers are never used as trust evidence. A deployment behind a reverse proxy needs explicit trusted-proxy configuration and its own security review before enabling the guard.

The guard is **not registered in the API**, does not mint CSRF cookies, and does not implement a browser session or enrollment route. A double-submit comparison alone does not authenticate a viewer, prove email ownership or authorize a Keycloak credential change. Future cookie issuance must enforce `Secure`, `Path=/`, host-only `__Host-` rules and a separately protected HttpOnly browser-session cookie. Distributed IP/global throttling, one-time credential completion, independent Keycloak email verification, session revocation, browser E2E and activation safeguards remain outstanding. Isolated TestServer policy tests are wired into CI. Four final-head PR checks passed on `77b22368` and four post-merge `main` checks passed on `6c2bbabd` on 2026-11-02, including full-stack PostgreSQL/Keycloak E2E. This verifies the unregistered request guard only, not the public browser enrollment ceremony.

## Opt-in CSRF bootstrap cookie issuer (proposed; CI not yet verified)

`OryvaBrowserCsrfBootstrap.CreateHandler(expectedOrigin)` constructs a **not registered** GET handler that validates a canonical HTTPS origin at setup and requires HTTPS, exact Host, no query string, `X-Oryva-Csrf-Bootstrap: 1`, exact Origin when present, and same-origin Fetch Metadata when present. It does not trust `X-Forwarded-*` headers. Rejections return a generic 403 with no cookie. Both success and denial suppress caching, referrers and cross-origin resource embedding.

On a permitted same-origin GET, the handler generates a fresh 256-bit CSPRNG token, sets a host-only `__Host-oryva-csrf` cookie (`Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=300`, no Domain), and returns `csrfToken` in a non-cacheable JSON response. Browser code must keep the JSON token **only in memory** and supply it as `X-Oryva-Csrf` for a subsequent guarded POST. JavaScript cannot read the HttpOnly cookie. The token is not persisted by this component and is not a browser-session secret.

This is a standalone double-submit CSRF bootstrap, **not session-bound authentication**. Before any public endpoint, implement independently protected HttpOnly browser-session cookies, distributed source-IP/global admission controls, reviewed reverse-proxy configuration, session binding/rotation and revocation, independent Keycloak email verification, one-time credential completion and E2E security tests. Never treat possession of the CSRF token as email ownership, invitation authorization or permission to enable an account. The test-only GET route is not registered in the production API.

## Threat boundaries and unfinished work

- **Proof scope:** possession of an invitation code is not independent confirmation that Keycloak's email is verified. Neither exchange nor inspection sets `emailVerified`, writes a credential, enables an account, grants roles, or creates a Keycloak session.
- **No HTTP exposure:** before an exchange endpoint is added, implement a reviewed browser ceremony that avoids bearer tokens in URLs/referrers/analytics, uses short-lived `HttpOnly`, `Secure`, appropriate `SameSite` cookies, origin and CSRF checks, generic errors, strict host/origin allowlisting and distributed IP/identity throttling.
- **No automatic credential enrollment:** a future Keycloak password-write and email-verification ceremony must revalidate the exact owned disabled Keycloak subject, required actions, exclusive viewer role, email and current database state under appropriate locks. The inspection result is not a substitute for an atomic one-time completion gate or reconciliation after ambiguous Keycloak outcomes.
- **Session theft/replay:** the browser secret remains a bearer secret until a separately reviewed, single-use completion protocol is built. No production route may treat it as a login.
- **Operational controls:** provision migration 020 before deploying the new issuer; monitor failed exchanges without logging tokens or recipient PII, define retention/purge and recovery procedures, review database privileges and run real Keycloak + browser E2E before exposing the flow.

## Validation

`tests/integration/Sun.Security.InvitationExchange.E2E` runs against isolated PostgreSQL and covers malformed/cross-viewer input, exactly-one-winner concurrency, audit and insert rollback, JSON non-disclosure, digest-only storage, expiry, reissue invalidation, subject/email change-away-and-back revocation and unchanged viewer activation state. The schema-validation workflow applies migrations 020 and 021 twice and checks fail-closed constraints. The exchange E2E additionally verifies 48-way quota contention, persisted denials, saturation and window rollover without consuming a valid invitation.

**Not delivered:** browser HTTP/cookie endpoints, email ownership verification against Keycloak, credential enrollment, password recovery, activation, production SMTP integration or release readiness. See [disabled-account enrollment gate](../operations/KEYCLOAK-DISABLED-ENROLLMENT.md) and the [master checklist](../../MASTER-CHECKLIST.md).
