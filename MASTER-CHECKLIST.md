# ORYVA Master Development Checklist

**Product:** SUN-001 · **Updated:** 2026-10-30 · **Legend:** [x] completed; [ ] pending. PR links are added when opened.

**Technology baseline:** .NET 10+, ASP.NET Core 10+, EF Core 10+ (where applicable), C# 14+. All new SUN product backend development follows this minimum.

## M0 — foundation
- [x] ORYVA-001 Product naming and technical namespace approved.
- [x] ORYVA-002 Ecosystem design-system PR #3 reviewed.
- [x] ORYVA-003 Architecture direction approved.
- [x] ORYVA-004 Repository created by owner.
- [ ] ORYVA-005 Repository governance and branch protection configured.
- [x] ORYVA-006 Design system migrated and squash-merged in [ORYVA PR #1](https://github.com/sunstriker2009/sun-oryva/pull/1) (source ecosystem PR #3 closed as superseded).
- [x] ORYVA-007 Architecture documentation and ADRs squash-merged in [ORYVA PR #1](https://github.com/sunstriker2009/sun-oryva/pull/1).
- [x] ORYVA-008 .NET workspace scaffolded ([PR #3](https://github.com/sunstriker2009/sun-oryva/pull/3), merged).
- [x] ORYVA-009 TypeScript workspace scaffolded ([PR #3](https://github.com/sunstriker2009/sun-oryva/pull/3), merged).
- [ ] ORYVA-010 CI quality gates operational (initial build/typecheck workflow merged in [PR #3](https://github.com/sunstriker2009/sun-oryva/pull/3); dependency lockfile, executable tests and additional gates pending).

## M1–M5 — implementation
- [ ] ORYVA-011 Docker/Keycloak/PostgreSQL development stack (local Compose baseline proposed; verify CI and runtime before completion).
- [ ] ORYVA-012 Keycloak integration.
- [ ] ORYVA-013 Idempotent sole-master bootstrap.
- [ ] ORYVA-014 OIDC authentication/session integration.
- [ ] ORYVA-015 Backend role-based authorization.
- [ ] ORYVA-016 User administration.
- [ ] ORYVA-017 Security auditing.
- [ ] ORYVA-018 Reusable React UI.
- [ ] ORYVA-019 Consumer integration examples.
- [ ] ORYVA-020 MarketPilot integration.

**Rule:** A proposed PR does not count as completed until merged and verified. No functional authentication features have been implemented.

## Cross-repository governance
- [x] SUN ecosystem links to ORYVA via [ecosystem PR #4](https://github.com/sunstriker2009/sun-ecosystem/pull/4), squash-merged.
- [x] Source [ecosystem PR #3](https://github.com/sunstriker2009/sun-ecosystem/pull/3) closed as superseded, without merging detailed specifications into ecosystem.
- [x] Product-line merge convention: squash merge PRs; no direct main commits.
