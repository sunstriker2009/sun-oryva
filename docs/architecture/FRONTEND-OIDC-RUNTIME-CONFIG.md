# Server-only OIDC runtime configuration

Authentication is disabled unless `ORYVA_OIDC_ENABLED=true` and all required server-side settings are valid:

- `ORYVA_OIDC_ISSUER`: canonical Keycloak HTTPS realm issuer.
- `ORYVA_OIDC_CLIENT_ID`: console's registered public OIDC client.
- `ORYVA_OIDC_REDIRECT_URI`: exact `https://<console-origin>/auth/callback` redirect.
- `ORYVA_CONSOLE_ORIGIN`: canonical HTTPS console origin.
- `ORYVA_OIDC_DATABASE_URL`: PostgreSQL connection string; production requires `sslmode=verify-full`.
- `ORYVA_OIDC_PAYLOAD_KEY` and `ORYVA_OIDC_BINDING_HMAC_KEY`: distinct, random 32-byte base64url secrets. Rotate through an approved deployment procedure.

Local HTTP loopback is permitted only with `ORYVA_OIDC_ALLOW_LOOPBACK_HTTP=true` outside production. Secrets must not be prefixed `NEXT_PUBLIC_`, logged, committed or serialized to browser responses.

Runtime discovery validates issuer and HTTPS endpoints. Before HTTP routes are enabled, add explicit RS256 discovery capability enforcement, deployment secret management, trusted request-origin checks, rate limiting, CSRF defenses and real Keycloak E2E. The existing authorization boundary remains fail-closed.
