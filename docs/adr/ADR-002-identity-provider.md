# ADR-002: Keycloak identity provider

**Status: Proposed — integration design pending**

Use Keycloak initially for credentials, authentication, OIDC tokens and sessions. ORYVA libraries depend on standards rather than proprietary authentication protocols. Privileged Keycloak Admin API access stays inside ORYVA management service. Evaluate realm topology, bootstrap, recovery and BFF design before accepting this ADR.
