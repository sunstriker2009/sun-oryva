# Keycloak management adapter — M1

**Status:** Minimal transport adapter; not a complete master bootstrap.

The .NET 10 `KeycloakManagementClient` uses a dedicated Keycloak client-credentials identity to obtain an access token from the ORYVA realm and call the Keycloak Admin REST API. It can find a user by exact username and create a **disabled** user. It does not set credentials, assign master roles, enable accounts, or grant access.

## Operator responsibilities

- Provision a confidential service-account client out of band, grant only the necessary `realm-management` permissions, and store its secret in a secret manager.
- Never use the Keycloak infrastructure bootstrap administrator for application API access.
- Enforce HTTPS for non-loopback addresses and prevent redirects to untrusted hosts.
- Inject `HttpClient` and options via DI; do not expose the adapter directly to browser clients.
- Validate stable user correlation, reconcile conflict/timeout outcomes, and verify role cardinality before any master activation.
- Add retry limits, response handling, auditing, secret rotation and integration tests before production use.

This PR intentionally does **not** add a client or credentials to the versioned realm import. The security review must approve any service-account permission grants before they are automated.
