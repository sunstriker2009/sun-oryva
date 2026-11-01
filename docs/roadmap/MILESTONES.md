# ORYVA Milestones

Updated 2026-11-01. States distinguish merged, tested work from pending PRs.

| Milestone | Scope | State |
| --- | --- | --- |
| M0 | Governance, architecture, workspace scaffolding and CI | Foundation implemented; hardening ongoing |
| M1 | Keycloak, PostgreSQL, secure sole-master bootstrap | Implemented; full-stack E2E passing |
| M2 | OIDC/JWT authentication, sessions, ASP.NET Core and Next.js integration | Backend JWT, master policy and signed-token E2E implemented; browser login/logout and frontend integration pending |
| M3 | Admin/viewer authorization policies and security tests | Active-admin (#63) and active-viewer (#65) PostgreSQL gates merged with HTTP E2E |
| M4 | User administration, password lifecycle, audit trail, console | Admin activation and DB-first deactivation merged (#62, #64). Viewer preparation (#66), disabled viewer role assignment (#67) and activation readiness preflight implemented; viewer activation/revocation, credential lifecycle, broader audit and console pending |
| M5 | MarketPilot integration, operational hardening and package release | Planned |

## Backend v1 exit checklist

- [x] Single-master bootstrap, role mapping and JWT validation
- [x] Master-only admin preparation, role assignment and guarded activation
- [x] Admin database authorization, database-first deactivation and recovery
- [x] Admin provisioning append-only audit and PostgreSQL/Keycloak E2E
- [x] Viewer authorization requires an active database subject (#65)
- [x] Guarded viewer preparation, exclusive role assignment and recovery by active master/admin (#66, #67)
- [x] Read-only, locked viewer activation readiness with Keycloak/PostgreSQL E2E (current PR; merge/CI verification pending)
- [ ] Guarded viewer activation and database-first revocation by active master/admin
- [ ] Secure invitations, credential enrollment, password change and recovery
- [ ] Production-grade audit coverage, rate limiting, least-privilege deployment and observability
- [ ] Final negative-path and full-stack release validation; package/deployment guidance

No production accounts or environments are changed by the integration tests.
The CI environment uses isolated test-only Keycloak identities and credentials.
