# OIDC login initiation

The server-only `initiateOidcLogin` module complements the merged callback orchestrator. It creates independent random state, nonce and PKCE verifier/challenge, builds the authorization-code + S256 URL, AES-GCM-seals the verifier and nonce, and persists the state and random browser binding via the PostgreSQL transaction store **before** returning the redirect target.

The returned object contains only the authorization URL and the Secure HttpOnly host-only cookie descriptor. The PKCE verifier and sealed payload are not returned to the browser.

**Release gates:** no HTTP route is exposed yet. Before enabling it, validate deployment configuration, trusted request origin and redirect URI, canonical issuer and discovery metadata, database migrations and encryption keys; set the cookie on a no-store 302 response; apply rate limiting; and complete callback cookie clearing, active-role backend authorization, logout and real Keycloak E2E. The console authorization resolver remains fail-closed.
