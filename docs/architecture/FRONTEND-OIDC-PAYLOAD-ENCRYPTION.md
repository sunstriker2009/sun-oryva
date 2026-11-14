# Encrypted OIDC transaction payloads

The server-side OIDC transaction store introduced in PR #139 accepts a sealed payload. This change provides an **AES-256-GCM** protector for PKCE verifier and nonce, using a random 96-bit IV, a 128-bit authentication tag, fixed domain-separated additional authenticated data and versioned envelope.

- The encryption key must be exactly 32 bytes, supplied by a deployment secret manager. Never commit or log it.
- A wrong key, modified ciphertext/tag, unsupported version, malformed envelope or invalid decoded transaction fails closed with a generic error.
- Each seal uses a fresh random IV; do not reuse IVs with the same key.
- Key rotation and in-flight transaction handling require an operational policy. Since transactions live at most five minutes, deployment can invalidate pending logins when rotating the key, or implement a reviewed versioned key ring.
- Unit tests cover round-trip, tampering, wrong key, malformed inputs and compatibility with the transaction-store adapter. The adapter test uses a fake database, **not** PostgreSQL.

**Still required before enabling routes:** real PostgreSQL migration/concurrency E2E, securely issued HttpOnly browser-binding cookie, server-side login/callback orchestration, independently validated OIDC tokens and secure sessions/logout. The code is not registered in a public route.
