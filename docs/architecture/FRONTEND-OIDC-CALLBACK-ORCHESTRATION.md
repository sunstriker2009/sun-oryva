# OIDC callback orchestration

The isolated server-side `completeOidcCallback` component composes previously merged OIDC boundaries without registering public HTTP routes.

1. Reject malformed or provider-error callback query.
2. Atomically consume the browser-bound, five-minute transaction from PostgreSQL. Consumption occurs **before** any network token request; failures require a new login.
3. Decrypt the sealed PKCE verifier and nonce.
4. Validate the authorization-code callback shape.
5. Exchange code using the PKCE verifier.
6. Cryptographically validate the returned ID token against the configured issuer, audience, nonce, expiry and JWKS.
7. Create a revocable, opaque server-side session containing **identity only**.

No access token is returned to browser JavaScript. Errors are generic. No role is derived from ID-token claims.

**Release gates:** HTTP routes with trusted-origin checks and cookie clearing, production database migration, a vetted OIDC client/protocol review, backend active-role authorization, CSRF protections, logout, Keycloak browser E2E, operational key rotation and incident logging. The existing server authorization resolver stays fail-closed.
