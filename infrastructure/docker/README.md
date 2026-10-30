# ORYVA local identity infrastructure

**Development only — not a production deployment.** This stack runs Keycloak in `start-dev` mode, bound to loopback, backed by PostgreSQL. The Keycloak bootstrap admin is an **infrastructure administrator**, **not** the unique ORYVA application master account.

## Start

1. Copy `.env.example` to `.env` in this directory.
2. Replace both placeholder passwords with distinct strong locally generated secrets. Never commit `.env`.
3. From this directory run `docker compose config --quiet` and then `docker compose up -d`.
4. Open `http://localhost:8080` (or your configured `ORYVA_KC_PORT`).

## Stop / reset

`docker compose down` stops containers while preserving the database volume. **Destructive:** `docker compose down -v` permanently deletes the local database volume.

## Security boundaries

- Development mode uses HTTP; do not expose beyond loopback, deploy to shared environments, or use production credentials.
- PostgreSQL has no published host port; it is reachable only inside the Compose network.
- Keycloak bootstrap credentials are required for local startup. They do not create ORYVA master/admin/viewer roles.
- No realm import, client configuration, master-account bootstrap, OIDC integration, authorization, or audit functionality is implemented by this PR.
- Production requires TLS, hostname configuration, dedicated DB credentials, secret manager integration, image digest pinning, hardened Keycloak startup and backup/restore strategy.
- Image tags are pinned for reproducibility within a release series; review updates and vulnerabilities regularly.

## ORYVA realm initialization

On an empty database, Keycloak imports the versioned `oryva` realm with three role definitions from `../keycloak/oryva-realm.json`. Existing realms are not overwritten. See [realm configuration](../keycloak/README.md). No users or application clients are created.
