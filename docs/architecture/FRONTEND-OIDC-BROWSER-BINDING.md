# ORYVA OIDC browser-binding cookie

This module adds an isolated cookie contract for the PostgreSQL-backed OIDC login transaction. It is **not yet registered as an HTTP login or callback route**.

- Cookie name: `__Host-oryva-oidc-binding`; no Domain attribute, Path=/, Secure, HttpOnly, SameSite=Strict, Max-Age=300.
- A fresh 256-bit random binding is generated per login attempt and passed to the transaction store, which stores only its HMAC.
- Callback processing must reject missing, duplicate, malformed and oversized cookie headers, and must clear the binding cookie on completion or failure.
- Strict SameSite may not work for all OIDC response modes, particularly cross-site form POST. This contract assumes top-level same-site-safe authorization-code GET redirects; integration E2E must confirm Keycloak behavior.
- Repeated login attempts in one browser overwrite the binding cookie, deliberately invalidating earlier attempts.
- The cookie is not an authenticated session, role proof, CSRF substitute for state, or authorization token.
- **Integration gates:** use trusted HTTPS origin and host validation, do not trust unverified forwarded headers, validate callback state, atomically consume the stored transaction, decrypt its payload, cryptographically verify ID token and establish a separate secure session. No public route is enabled here.

Cookie issuance and clearing are represented as immutable descriptors for the Next.js HTTP adapter to apply in a future PR.
