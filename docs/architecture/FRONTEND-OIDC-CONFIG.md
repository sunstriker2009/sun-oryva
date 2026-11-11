# ORYVA frontend OIDC configuration boundary

This milestone introduces strict validation for **public** OIDC configuration:
issuer, public client ID and exact login/logout callback destinations.
Production URLs must use HTTPS; an explicit opt-in permits loopback HTTP for
local development only. Configuration does not include a client secret.

This is not login or OIDC discovery. A subsequent server-side integration
must use a vetted OIDC library implementing Authorization Code + PKCE,
state/nonce validation, issuer/audience verification, callback and logout
protection, and HttpOnly Secure SameSite session cookies. Browser code must
not store tokens in localStorage or trust role claims without server validation.

Only redirect URLs registered with the identity provider are acceptable.
The helper does not fetch metadata or perform network requests. Server-side
settings must separately validate trusted proxy headers and callback origins.

Backend v1 remains provisionally frozen: independent email proof, credential
enrollment, recovery and activation of unverified accounts remain disabled.
