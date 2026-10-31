# Protected API — M2 integration

The standalone `Sun.Security.Api` host composes Keycloak JWT bearer authentication with the database-backed `Oryva.ActiveMaster` authorization policy.

Set `ORYVA_OIDC_ISSUER` to the **HTTPS** Keycloak realm issuer (ending in `/realms/oryva`), `ORYVA_OIDC_AUDIENCE` to the API audience, and `ORYVA_DATABASE_URL` to a PostgreSQL connection string supplied through a secret manager. Provision the PostgreSQL schema and master identity separately before running the API.

- `GET /health/live` is anonymous and does not query the database.
- `GET /api/master/session` requires a signed, valid Keycloak access token with direct realm role `master` **and** a matching active master subject in PostgreSQL. Missing token is 401, authenticated non-master/mismatch is 403, and database errors must not grant access.
- Use HTTPS at the reverse proxy or ingress and restrict database credentials. Do not publish this demo host as a production-ready user administration API.

This increment wires the policy to an actual endpoint. **Outstanding:** HTTP integration tests, operational error handling, broader role policies, audit events, user management, and session lifecycle.
