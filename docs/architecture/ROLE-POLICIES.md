# ORYVA role policies — active database authorization

The JWT bearer middleware validates issuer, audience, signature, lifetime and
RS256 before mapping the Keycloak realm role into the trusted
`oryva_realm_role` claim. Client roles and unverified internal-role claims
are not accepted. Missing, duplicate, or conflicting role claims fail closed.

| Operation | Required policy |
| --- | --- |
| Master-only user administration | `Oryva.ActiveMaster`: validated exclusive master role and active PostgreSQL master subject |
| Admin operations | `Oryva.Admin`: validated exclusive admin role and committed active PostgreSQL admin subject |
| Read-only viewer operations | `Oryva.Viewer`: validated exclusive viewer role and active PostgreSQL viewer subject, **or** validated admin role and active PostgreSQL admin subject |

The master role does not implicitly inherit admin/viewer privileges. An
active admin may access read-only viewer endpoints, but an active viewer cannot
access admin endpoints. Each authorization request rechecks the corresponding
PostgreSQL subject state, so database-first revocation denies previously
issued tokens without waiting for JWT expiry. PostgreSQL outages do not
permit role-only fallback.

The viewer database registry and `/api/viewer/session` policy demonstration
are documented in [Viewer authorization](VIEWER-AUTHORIZATION.md).
Viewer provisioning, activation, audit and Keycloak logout are **not yet
implemented**. Do not grant viewer access by directly editing the database in
production; the isolated E2E runner uses SQL fixtures solely to test the
authorization boundary.
