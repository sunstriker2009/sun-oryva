# OIDC PKCE transaction primitives

This increment adds cryptographically random OAuth state, OIDC nonce and
PKCE S256 verifier/challenge generation, plus an authorization URL builder.
The verifier is intentionally absent from the authorization URL.

**This does not enable login.** No redirect route is activated, no browser
cookies or callback are implemented, and the console remains default-deny.
The next milestone must integrate a maintained OIDC library for discovery,
callback verification, token validation, secure server-side session storage,
logout revocation and CSRF defenses. Store state, nonce and verifier in a
short-lived server-controlled transaction bound to the initiating browser;
never trust query parameters or localStorage as proof.

These helpers are tested independently and do not replace a vetted OIDC
client. Backend enrollment and account recovery remain deferred.
