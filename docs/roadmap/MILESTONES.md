# ORYVA Milestones

Updated 2026-10-31. States reflect merged and tested work, not proposals.

| Milestone | Scope | State |
| --- | --- | --- |
| M0 | Governance, architecture, design migration, workspace scaffolding, CI | Foundation implemented; hardening ongoing |
| M1 | Keycloak, PostgreSQL, Docker, secure sole-master bootstrap | Implemented; full-stack E2E passing (PR #36) |
| M2 | OIDC/JWT authentication, sessions, ASP.NET Core and Next.js integration | In progress: JWT bearer, active-master policy, protected API and real-token HTTP E2E merged (PRs #37–#42); browser login/logout and frontend integration pending |
| M3 | Admin/viewer role policies, permission enforcement, security tests | Planned; active-master enforcement is already implemented |
| M4 | User administration, password lifecycle, audit trail, console | Planned |
| M5 | MarketPilot integration, hardening, package release guidance | Planned |

The HTTP E2E tests use an isolated Keycloak test client and test-only account completion. Production requires HTTPS issuer metadata and must not use the CI password-grant setup. The production Keycloak user-profile attribute `oryva.bootstrap.owner` must be configured before bootstrap.
