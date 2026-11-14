# ORYVA frontend OIDC authorization-code exchange boundary

This module is an **unregistered server-only transport primitive**, not a complete authentication flow.

## Implemented
- Form-encoded authorization-code POST with PKCE verifier and exact redirect URI.
- HTTPS-only token endpoint and redirect URI, except explicit loopback development.
- No redirects, no-store, five-second default deadline (maximum 15 seconds).
- Strict JSON content type and bounded 64 KiB streamed response.
- Generic failures without leaking identity-provider messages.
- Minimal token response shape checks. Tokens are **untrusted** at this stage.

## Required before production login
1. Browser-bound transaction stored server-side and atomically consumed once, including replay protection across replicas.
2. A maintained OIDC client or JOSE verifier for issuer, signature/JWKS, audience, nonce, expiry and algorithm validation; no unverified tokens may create sessions.
3. Secure server-side session, HttpOnly cookie, logout/revocation, CSRF controls and authenticated route registration.
4. Keycloak integration E2E including negative paths, concurrency and session expiry.

No callback or login route is enabled by this PR. Never log tokens, authorization codes or PKCE verifiers.
