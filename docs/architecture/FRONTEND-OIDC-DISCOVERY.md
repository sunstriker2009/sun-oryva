# ORYVA OIDC discovery milestone

The Next.js console has a server-only OpenID Connect discovery module.
It fetches issuer metadata with a timeout, rejects redirects, avoids caching,
enforces HTTPS (except explicit loopback development), and validates exact
issuer identity, authorization/token/JWKS endpoint URLs, code flow, and
supported signing algorithms. It does not send credentials or tokens.

This is **not login**. No authorization-code redirect, PKCE transaction,
state/nonce cookie, token validation, session persistence, or logout has
been implemented. Do not expose protected routes until those are in place.
The authorization resolver remains default-deny.

Before production, use a maintained, vetted OIDC library for the full
authorization flow and token verification. Avoid hand-rolling JWT validation.
The metadata URL comes only from trusted server configuration, never from a
user-supplied query parameter, to prevent SSRF. Network egress controls
should restrict destinations as appropriate.
