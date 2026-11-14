# ORYVA OIDC ID-token verification boundary

This is a server-side, isolated **RS256-only** verifier for an OIDC ID token received after an authorization-code exchange. It pins the issuer, client ID (audience), expected transaction nonce and trusted JWKS endpoint. The token cannot select its own verification endpoint or algorithm.

Checks include: signature against exactly one matching RSA JWKS key (minimum 2048-bit modulus), issuer, audience and authorized party for multiple audiences, nonce, subject, issued-at, expiry, not-before and bounded token lifetime. JWKS retrieval requires HTTPS, rejects redirects and applies a five-second timeout. Failures are generic.

**Not sufficient for production authentication on its own:**
- This is a narrow verifier rather than a maintained, fully conformant OIDC client. Review protocol coverage and prefer a vetted OIDC library for production token validation, including `at_hash` when applicable, algorithm negotiation, key rotation, clock skew policy and response-mode constraints.
- No login or callback HTTP route is registered. The callback must first validate and atomically consume the browser-bound transaction, decrypt the nonce/verifier, exchange the code and verify the ID token.
- No role or permission is trusted from ID-token claims. Authorization must use the backend's database-backed active-subject checks.
- No browser session, cookie, refresh, revocation or logout is established.
- Keycloak E2E with real signed tokens is required before enabling authentication.
