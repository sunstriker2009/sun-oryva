# ORYVA OIDC callback response validation

This module validates the shape of an authorization-code callback against
a trusted, browser-bound server transaction: exact state comparison, a single
code, a five-minute transaction age limit, replay marker and rejection of
implicit-flow tokens. Error messages do not include provider-supplied text.

**Not a complete login:** This is an isolated validation primitive. It
cannot itself enforce single-use: the caller must atomically consume the
transaction in durable server-side storage before exchanging a code. The
transaction must be bound to the browser through a secure cookie and must
never be accepted from request parameters. A maintained OIDC client must
verify issuer, audience, signature, nonce and token expiry during token
exchange. Session establishment and logout are not implemented.

No callback route is exposed. Protected routes remain fail-closed.
