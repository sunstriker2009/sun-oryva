# ORYVA Master Development Checklist

**Product:** SUN-001 · **Updated:** 2026-11-01 · **Legend:** [x] merged and verified; [ ] outstanding.

**Baseline:** .NET 10+, ASP.NET Core 10+, C# 14+, Keycloak 26.3.5, PostgreSQL 17. EF Core 10+ where applicable.

## M0 — foundation
- [x] ORYVA-001 Product naming and namespaces approved.
- [x] ORYVA-002 Design system migrated (PR #1).
- [x] ORYVA-003 Architecture direction and ADRs documented (PR #1).
- [x] ORYVA-004 Repository created.
- [x] ORYVA-005 Main branch protection and required checks configured.
- [x] ORYVA-006 .NET workspace scaffolded (PR #3).
- [x] ORYVA-007 TypeScript workspace scaffolded (PR #3).
- [x] ORYVA-008 CI build and integration workflows operational.
- [ ] ORYVA-009 Additional release/package quality gates and production smoke tests.

## M1 — sole-master bootstrap
- [x] ORYVA-010 Keycloak/PostgreSQL development stack and realm baseline.
- [x] ORYVA-011 Ownership-verified, idempotent master bootstrap and singleton PostgreSQL reservation.
- [x] ORYVA-012 Distributed provisioning lock and concurrency checks.
- [x] ORYVA-013 Full-stack Keycloak/PostgreSQL master bootstrap E2E ([PR #36](https://github.com/sunstriker2009/sun-oryva/pull/36)).
- [ ] ORYVA-014 Production realm user-profile setup for `oryva.bootstrap.owner` and deployment runbook.
- [x] ORYVA-014a Effective Keycloak ownership-profile validation for both `oryva.bootstrap.owner` and `oryva.provisioning.id`, explicit apply, isolated disabled identity persistence test and [operator runbook](docs/operations/KEYCLOAK-USER-PROFILE.md) ([PR #76](https://github.com/sunstriker2009/sun-oryva/pull/76); all five workflows passed on implementation commit `36161db8`, including Keycloak/PostgreSQL E2E). Production rollout and runtime least-privilege review remain separate and outstanding.

## M2 — authentication and active-master authorization
- [x] ORYVA-015 Database-backed active-master subject authorization ([PR #37](https://github.com/sunstriker2009/sun-oryva/pull/37)).
- [x] ORYVA-016 ASP.NET Core active-master authorization policy ([PR #38](https://github.com/sunstriker2009/sun-oryva/pull/38)).
- [x] ORYVA-017 Keycloak JWT bearer validation ([PR #39](https://github.com/sunstriker2009/sun-oryva/pull/39)).
- [x] ORYVA-018 Protected API endpoint ([PR #40](https://github.com/sunstriker2009/sun-oryva/pull/40)).
- [x] ORYVA-019 HTTP middleware authorization tests ([PR #41](https://github.com/sunstriker2009/sun-oryva/pull/41)).
- [x] ORYVA-020 Real signed Keycloak JWT HTTP E2E ([PR #42](https://github.com/sunstriker2009/sun-oryva/pull/42)).
- [ ] ORYVA-021 Browser OIDC login/logout, secure session lifecycle and Next.js integration.

## M3 — role enforcement
- [ ] ORYVA-022 Admin/viewer policy and authorization matrix.
- [ ] ORYVA-023 Privilege-escalation, disabled-account and invalid-token E2E coverage.

## M4 — management and audit
- [ ] ORYVA-024 Master-only admin creation and administration.
- [ ] ORYVA-025 Master/admin viewer lifecycle management.
- [ ] ORYVA-026 Password change, security audit events and administration UI.

### M4 backend implementation ledger

- [x] Reserve unique admin identities in PostgreSQL and create disabled Keycloak candidates with exact provisioning ownership markers.
- [x] Verify canonical Keycloak subject, email, disabled status, and absence of direct/effective ORYVA roles before marking prepared.
- [x] Real PostgreSQL/Keycloak E2E coverage for admin preparation, reservation collisions, and ownership ([PR #55](https://github.com/sunstriker2009/sun-oryva/pull/55)).
- [x] Master-only, read-only reconciliation inspection ([PR #56](https://github.com/sunstriker2009/sun-oryva/pull/56)).
- [x] Explicit fail-closed recovery of interrupted disabled candidates ([PR #57](https://github.com/sunstriker2009/sun-oryva/pull/57)).
- [x] Cross-instance recovery serialization and contention tests ([PR #58](https://github.com/sunstriker2009/sun-oryva/pull/58), merged with green CI).
- [x] Durable, append-only admin provisioning audit and master-only history endpoint ([PR #59](https://github.com/sunstriker2009/sun-oryva/pull/59)).
- [x] Guarded admin role assignment and activation, including ambiguous-response recovery ([PR #60](https://github.com/sunstriker2009/sun-oryva/pull/60), [PR #62](https://github.com/sunstriker2009/sun-oryva/pull/62)).
- [x] Database-backed active-admin authorization and master-only admin deactivation ([PR #63](https://github.com/sunstriker2009/sun-oryva/pull/63), [PR #64](https://github.com/sunstriker2009/sun-oryva/pull/64)).
- [x] Database-backed viewer authorization, without granting role-only access ([PR #65](https://github.com/sunstriker2009/sun-oryva/pull/65)).
- [x] Guarded viewer reservation, disabled Keycloak preparation and explicit recovery ([PR #66](https://github.com/sunstriker2009/sun-oryva/pull/66), merged with green CI).
- [x] Guarded viewer realm-role assignment, disabled-state verification, cross-instance lock and durable audit ([PR #67](https://github.com/sunstriker2009/sun-oryva/pull/67), CI verified).
- [x] Read-only, lease-serialized viewer activation readiness with strict ownership, exclusive role, password, email and required-action gates ([PR #68](https://github.com/sunstriker2009/sun-oryva/pull/68), E2E verified).
- [x] Guarded viewer activation with durable intent, Keycloak reconciliation, actor audit and real E2E ([PR #69](https://github.com/sunstriker2009/sun-oryva/pull/69), six PR checks verified before merge).
- [x] Database-first viewer deactivation and session revocation with durable recovery and audit ([PR #70](https://github.com/sunstriker2009/sun-oryva/pull/70); verified before merge).
- [x] Transactional viewer reservation audit ([PR #72](https://github.com/sunstriker2009/sun-oryva/pull/72)); migration 011, real PostgreSQL/Keycloak E2E and schema validation passed all five workflows on implementation commit `c2f7babc`. Five post-merge `main` workflows passed on merge commit `0ea9a47d` (observed 2026-11-01). Preparation completion and failed Keycloak operations need additional audit coverage.
- [ ] Secure viewer credential enrollment and invitations; full lifecycle and operational recovery tooling.
- [x] Atomic viewer preparation completion audit (migration 012, [PR #73](https://github.com/sunstriker2009/sun-oryva/pull/73)); five PR checks passed on `e93f3016`, squash-merged as `237780bd`, and all five post-merge `main` workflows passed, including real Keycloak/PostgreSQL E2E (verified 2026-11-01).
- [ ] Password-change and account recovery policies, audit events, API error contracts, and full lifecycle security E2E.
- [x] PostgreSQL-backed cross-replica management write quotas (migration 013, HTTP concurrency, 429 and outage-503 E2E; [PR #75](https://github.com/sunstriker2009/sun-oryva/pull/75), five workflows passed on implementation commit `e8f0e462` before merge). Edge, login, invitation and password-recovery quotas remain outstanding.
- [x] Process-local management write throttling with authenticated-subject partitioning and HTTP tests ([PR #71](https://github.com/sunstriker2009/sun-oryva/pull/71), verified).
- [ ] Production Keycloak permissions, operational migrations, threat review, release gates and deployment runbooks.

The M4 ledger records partial backend progress; it does **not** mean ORYVA-024 through ORYVA-026 are complete.

## M5 — consumer integration
- [ ] ORYVA-027 Reusable frontend/backend package releases.
- [ ] ORYVA-028 MarketPilot AI integration and deployment hardening.

**Security invariants:** exactly one active master per deployment; only the master creates admins; master/admin manage viewers; viewers are read-only. Database and validated token subject must match for active-master operations. CI-only password grants and HTTP discovery must never be enabled in production.
