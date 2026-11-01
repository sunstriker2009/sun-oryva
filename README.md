# ORYVA by Sun

**SUN-001 · Identity. Trust. Protection.**

ORYVA is an independently deployable identity and security platform with reusable ASP.NET Core and React/Next.js integration packages. MarketPilot AI is its first planned consumer, not a dependency.

**Status (2026-10-31):** M1 secure sole-master bootstrap implemented and integration-tested. M2 backend Keycloak JWT bearer authentication, active-master authorization policy, protected API endpoint, and real-token HTTP E2E tests merged. Full browser login/logout, user administration, React UI, and consumer integration remain pending.

## Implemented foundations
- Keycloak realm, PostgreSQL master reservation, and distributed provisioning lock.
- Idempotent, ownership-verified single-master provisioning and concurrency tests.
- Strict Keycloak JWT validation, realm master-role mapping, and database-backed active-master authorization.
- ASP.NET Core API with anonymous liveness and protected `/api/master/session`.
- CI integration tests against Keycloak and PostgreSQL, including real signed JWT requests.

## Documentation
- [Architecture overview](docs/architecture/OVERVIEW.md)
- [Active-master authorization](docs/architecture/ACTIVE-MASTER-AUTHORIZATION.md)
- [Protected API](docs/architecture/PROTECTED-API.md)
- [Security model](docs/architecture/SECURITY-MODEL.md)
- [Integration boundaries](docs/architecture/INTEGRATION.md)
- [Milestones](docs/roadmap/MILESTONES.md)
- [Master development checklist](MASTER-CHECKLIST.md)
- [Design system](docs/design-system/README.md)
- [Architecture decisions](docs/adr/)

Backend namespace: `Sun.Security.*`; frontend scope: `@sun-security/*`. Packages are not yet published. Changes use feature branches and reviewed PRs, not direct commits to main.
