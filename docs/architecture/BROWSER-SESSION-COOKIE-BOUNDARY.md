# Opt-in browser bearer cookie boundary

**Status:** proposed implementation, CI and merge not yet verified. No production API route, browser authentication, Keycloak credential mutation, email ownership verification, SMTP dispatch or account activation.

## Contract

`OryvaBrowserSessionCookie` is an opt-in ASP.NET Core HTTP transport helper. It only operates in the same request after `OryvaBrowserRequestGuard` has validated a marked POST endpoint: canonical HTTPS Host/Origin, same-origin Fetch Metadata (if supplied), and constant-time CSRF double-submit comparison. An unmarked or rejected request cannot issue, read or clear a browser bearer cookie through this helper.

`TryIssue(context, bearer, databaseExpiresAt)` must be called **only after** the existing PostgreSQL exchange or rotation has committed. It requires a 43-character base64url-shaped opaque bearer and a positive, at-most-five-minute remaining database TTL. Cookie lifetime is rounded **down**, never extended; the caller must pass the original persisted expiry after rotation. It issues or replaces `__Host-oryva-browser` with `Secure; HttpOnly; SameSite=Strict; Path=/`, no Domain, explicit expiry and max-age. Neither the cookie helper nor the guarded endpoint may return the bearer in JSON, logs or URLs.

`TryReadUntrustedBearer` rejects missing, malformed and duplicate session cookies. It deliberately returns **untrusted bearer material**: a valid cookie shape is not authentication, not proof of invitation possession, and not a permission to write a password or activate a viewer. The caller must validate the digest and current viewer/challenge/Keycloak binding in PostgreSQL under the appropriate locks. Do not use `IsLiveAsync` as an authorization decision.

`TryClear` expires both the session and CSRF cookies, using the same host-only root-path attributes. Clearing a browser cookie is **not server-side revocation**; first commit `RevokeAsync` or the appropriate terminal state transaction. When a Keycloak operation has an ambiguous outcome, do not treat cookie clearing as proof that enrollment completed.

All three methods set non-cacheable, no-referrer response headers when mutating cookies. The request guard is responsible for rejecting cross-origin/CSRF attempts before these methods can execute.

## Threats and rollout gates

- **No public enrollment:** The helper is not registered as an API endpoint and cannot itself authenticate or enable an identity. The production route must be separately reviewed and protected by distributed source-IP/global and viewer quotas, trusted-proxy configuration, CSRF/origin checks, and one-time exchange completion.
- **Race and replay:** Cookie replacement must follow a committed PostgreSQL rotation. A stale cookie cannot be rejected by its shape alone; database digest checks enforce replay resistance. The original five-minute expiry remains fixed.
- **Revocation:** The server-side revocation transaction must succeed before clearing cookies; revocation after a stolen bearer races with rotation is resolved by the database lock and state predicates, not by HTTP headers.
- **Email and credentials:** Independent Keycloak email ownership proof, disabled-account credential enrollment, exact subject and role revalidation, ambiguous-write reconciliation, and safe activation are outstanding. Do not enable unverified accounts.
- **Operations:** Production TLS/proxy trust, cookie scope and SameSite compatibility, incident monitoring, retention, security E2E with real Keycloak/PostgreSQL, SMTP relay integration and least-privilege review remain release blockers.

## Validation

`tests/unit/Sun.Security.BrowserBoundary.PolicyTests` uses an isolated ASP.NET TestServer to exercise guarded issuance, cookie replacement, fixed-expiry bounds, duplicate/malformed cookie rejection, origin and CSRF rejection, unmarked endpoint denial, and host-only clearing. It intentionally does **not** simulate Keycloak email verification or claim production enrollment readiness.

**Do not mark this milestone verified until final-head PR CI passes and GitHub confirms mergeability.**
