# OIDC browser binding cookie and callback navigation

The OIDC transaction binding cookie uses `__Host-` prefix, `Secure`, `HttpOnly`, `Path=/`, no Domain, a five-minute lifetime, and **SameSite=Lax**.

Why Lax: the authorization-code flow returns from the Keycloak site via a **top-level cross-site GET navigation** to `/auth/callback`. Browsers normally omit SameSite=Strict cookies on that navigation, preventing the server from recovering its independently generated browser-binding secret. Lax permits this GET callback while continuing to block most cross-site subresource and unsafe-method cookie sends.

The callback MUST be GET-only, validate the exact expected origin/redirect URI, consume state atomically and verify nonce/PKCE/token before session issuance. Clear the binding cookie after callback (success or failure). Never use Lax as a replacement for CSRF defenses on state-changing endpoints.

A real browser E2E against Keycloak is still required before enabling public routes.
