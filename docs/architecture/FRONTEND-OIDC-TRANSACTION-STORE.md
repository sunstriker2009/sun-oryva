# Frontend OIDC browser transaction storage

This PR introduces a PostgreSQL schema and injected query adapter for single-use, cross-replica authorization-code transactions. It is **not yet wired to any HTTP route**.

- `issue` inserts a SHA-256 digest of state, HMAC-SHA-256 of independent browser-binding cookie secret, and **caller-supplied encrypted** transaction payload (PKCE verifier and nonce). It rejects duplicate states.
- `consume` atomically updates a single matching, unexpired, unused row and returns the encrypted payload. PostgreSQL row locking serializes competing updates. It is deliberately consumed **before** any token exchange; failed exchange requires restarting login.
- A five-minute fixed lifetime applies. No session can be created by this module.
- `createBrowserBinding()` produces a 256-bit browser secret. Cookie issuance must use Secure, HttpOnly, SameSite and host-only settings when integrated.
- Schema is a proposed deployment migration, not applied automatically; a real PostgreSQL concurrency E2E and migration validation are still required.
- Encryption/decryption and key rotation for sealed payloads must be supplied by a reviewed server-side cryptographic component. Do not pass plaintext verifier/nonce as `sealedPayload`.
- A vetted OIDC library must validate token signature, issuer, audience, nonce and expiry before any session is established.

Next: authenticated encryption, database integration tests, secure cookie binding and callback wiring. Do not expose login routes before these gates.
