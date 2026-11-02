# ORYVA Master Development Checklist

**Product:** SUN-001 · **Updated:** 2026-11-02 · **Legend:** [x] merged and verified; [ ] outstanding.

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
- [x] Internal invitation-to-browser exchange (migration 020; [PR #98](https://github.com/sunstriker2009/sun-oryva/pull/98), squash-merged as `c122b4bc`): digest-only five-minute one-time exchange, reissue and identity-change revocation, transactional consumption audit, rollback and 16-way PostgreSQL concurrency E2E. **All six final PR-head checks passed on `e6049554`**, including schema idempotence and full-stack Keycloak/PostgreSQL E2E. Post-merge main checks are tracked separately. **No public route, browser cookie, Keycloak email verification, password enrollment or activation.** See [threat boundaries](docs/architecture/VIEWER-INVITATION-BROWSER-EXCHANGE.md).
- [x] Cross-replica invitation browser-exchange attempt quota (migration 021; [PR #100](https://github.com/sunstriker2009/sun-oryva/pull/100), squash-merged as `c1286646`): 32 attempts per viewer per 60-second window, saturated count 33, generic denials, 48-way PostgreSQL contention/rollover E2E and idempotent schema checks. **All six final-head PR checks passed on `3450a253`**, including PostgreSQL/Keycloak full-stack E2E and schema validation. Post-merge main CI is tracked separately. **No public route, IP throttle, CSRF/origin controls, independent email proof, credential enrollment or activation.**
- [x] Internal opt-in browser POST request boundary ([PR #102](https://github.com/sunstriker2009/sun-oryva/pull/102), squash merge `6c2bbabd`): strict HTTPS/Host/Origin, same-origin Fetch Metadata, constant-time double-submit CSRF matching, duplicate-cookie rejection, redacted generic denials, no-store/no-referrer headers and isolated TestServer security regressions. **All four final-head PR workflows passed on `77b22368`; all four post-merge `main` workflows passed on `6c2bbabd`**, including full-stack PostgreSQL/Keycloak E2E (observed 2026-11-02). Guard remains unregistered; no public route, CSRF cookie issuance, email proof, credential mutation or account activation.
- [ ] Opt-in CSRF bootstrap cookie issuance proposed in this PR (not yet CI verified): standalone same-origin GET with 256-bit random token, HttpOnly host-only Secure/SameSite=Strict five-minute cookie, no-cache response and isolated TestServer regression. Not registered publicly and not a session, email proof or activation grant.
- [ ] Public browser ceremony and secure viewer credential enrollment. Distributed IP/global throttling, trusted-proxy deployment, session cookie issuance and lifecycle, independently verified Keycloak email ownership, atomic credential completion and full lifecycle/operational recovery remain outstanding.
- [x] Opt-in, operator-threshold invitation outbox alert evaluation ([PR #97](https://github.com/sunstriker2009/sun-oryva/pull/97)): pure aggregate policy, fail-closed stale/inconsistent snapshot handling, unit tests and real PostgreSQL/Mailpit E2E. All four implementation-head workflows passed on `0be34915`, including CI and full-stack E2E. Final documentation-head and post-merge checks must be verified separately. **No alert publisher, production thresholds, relay probe, incident escalation, browser enrollment or account activation.**
- [x] Internal aggregate-only invitation outbox health snapshot with PostgreSQL due/retry/expired-lease/exhaustion/cancellation state-transition E2E and non-disclosure regression ([PR #95](https://github.com/sunstriker2009/sun-oryva/pull/95), squash-merged as `bcd73203`; all five final-head checks passed, including real PostgreSQL/Mailpit E2E). See [internal monitoring contract](docs/operations/INVITATION-OUTBOX-HEALTH.md). **Counters are not a hosted dispatcher, alerting configuration, inbox delivery proof, enrollment or activation; production thresholds, alerting and incident response remain outstanding.**
- [x] Opt-in authenticated STARTTLS invitation transport with strict single-mailbox validation, downgrade/untrusted-certificate rejection tests and redacted errors ([PR #94](https://github.com/sunstriker2009/sun-oryva/pull/94)). All four initial PR workflows passed on implementation head `2040ae41`, including SMTP protocol CI and full-stack PostgreSQL/Keycloak E2E; final documentation-head and post-merge checks remain separate. **Not registered or enabled; no external SMTP, email ownership proof, credential enrollment or activation.** See [SMTP operator gate](docs/operations/SMTP-STARTTLS-TRANSPORT.md).
- [x] Explicit single-iteration Mailpit invitation dispatcher (fenced claim, invalid sweep, redacted transport retry and concurrent PostgreSQL/Mailpit E2E; [PR #92](https://github.com/sunstriker2009/sun-oryva/pull/92), squash-merged as `3b831ad9`). All four applicable PR workflows passed on final head `71d728f3`, including real PostgreSQL/Mailpit E2E. Post-merge main CI remains separately unverified. **No hosted service, external SMTP, enrollment or activation.**
- [x] Transaction-held isolated SMTP handoff (migration 019, Mailpit-only adapter, terminal relay-accepted state and append-only delivery audit; [PR #90](https://github.com/sunstriker2009/sun-oryva/pull/90), squash-merged as `716d12b6`). **All five PR workflows passed on final head `793b8ce6`**, including schema idempotence and real PostgreSQL/Mailpit full-stack E2E. Post-merge main CI is tracked separately. **No production SMTP dispatch, browser ceremony, email proof, credential enrollment or activation.**
- [x] Fenced invitation outbox claim/retry foundation (migration 018, PostgreSQL SKIP LOCKED, lease fencing, expiry and invalid-delivery sweeps; [PR #89](https://github.com/sunstriker2009/sun-oryva/pull/89)). Six initial implementation-head CI jobs passed on `05d687a7`, including PostgreSQL/Keycloak full-stack E2E and schema validation; final head and merge CI must be verified separately. **No SMTP sender or browser enrollment**.
- [x] Encrypted, atomic invitation delivery outbox foundation (migration 017, AES-256-GCM, metadata-only queued issuance, reissue/consumption cancellation and PostgreSQL E2E; [PR #88](https://github.com/sunstriker2009/sun-oryva/pull/88)). All five implementation-head workflows passed on `b9c4b603`, including full-stack Keycloak/PostgreSQL E2E and schema validation; final checklist-head CI and merge verification are separate. **No SMTP worker, email proof or account activation**. See [threat model](docs/architecture/VIEWER-INVITATION-CHALLENGES.md).
- [x] Isolated Keycloak negative enrollment gate: disabled unverified/verified test identities with credentials cannot obtain tokens or sessions ([PR #77](https://github.com/sunstriker2009/sun-oryva/pull/77); four PR workflows passed on `89e62451`, including real Keycloak E2E). No production activation or mail delivery.
- [x] Invitation bearer-token JSON response redaction guard ([PR #87](https://github.com/sunstriker2009/sun-oryva/pull/87)): default/web/nested System.Text.Json and ToString regression coverage passed in isolated PostgreSQL/Keycloak full-stack E2E on implementation head `1f17d125` (four PR workflows passed). No SMTP delivery, enrollment or activation is enabled; final documentation-head CI and merge verification tracked separately.
- [ ] Safe viewer invitation and credential enrollment: native disabled-account Keycloak action-email was **rejected** in isolated CI (PR #79); an independent email-proof and browser credential ceremony remains unvalidated. Do not expose invitation endpoints. See [enrollment gate](docs/operations/KEYCLOAK-DISABLED-ENROLLMENT.md).
- [x] Isolated disabled-account action-email behavior probe ([test](tests/integration/keycloak_disabled_action_link_e2e.py), [runbook](docs/operations/KEYCLOAK-ACTION-LINK-MAIL-SINK.md)): Keycloak 26.3.5 **rejected** `execute-actions-email` for a disabled unverified test identity; no email, password, verified state or session resulted. Five PR workflows passed on `544b03bc`, including [real Keycloak E2E](https://github.com/sunstriker2009/sun-oryva/actions/runs/41398729427). This blocks the native disabled-user invitation path; browser form completion, one-time link replay/expiry and a separate fail-closed enrollment design remain outstanding.
- [x] Atomic viewer preparation completion audit (migration 012, [PR #73](https://github.com/sunstriker2009/sun-oryva/pull/73)); five PR checks passed on `e93f3016`, squash-merged as `237780bd`, and all five post-merge `main` workflows passed, including real Keycloak/PostgreSQL E2E (verified 2026-11-01).
- [x] Internal one-time viewer invitation challenge foundation (migration 014, CSPRNG digest-only token, transactional reissue, atomic replay/expiry/email/state guards, PostgreSQL E2E): [PR #80](https://github.com/sunstriker2009/sun-oryva/pull/80) merged as `02b79577`; **all five PR workflows passed** on head `7092427e`, including real PostgreSQL/Keycloak full-stack E2E. **No public invitation endpoint, mail delivery, credential enrollment or activation is implemented.** [Threat model](docs/architecture/VIEWER-INVITATION-CHALLENGES.md).
- [x] Transactional append-only viewer invitation event auditing (migration 015): issuance, reissue revocation and token consumption with rollback and actor-attribution tests ([PR #82](https://github.com/sunstriker2009/sun-oryva/pull/82)). All five implementation workflows passed on `23dc427e`, including real PostgreSQL/Keycloak full-stack E2E. **No email delivery, verified enrollment, public redemption or activation** is implemented.
- [x] Invitation issuer database-active subject gate ([PR #83](https://github.com/sunstriker2009/sun-oryva/pull/83)): exact active master/admin subject and role under a transaction-held row lock; forged/mismatched/deactivated issuer E2E; five PR checks passed on `65ab8c42`, squash-merged as `937fd43f`. JWT validation at the future API boundary remains mandatory. Post-merge main CI is tracked separately.
- [x] Invitation subject substitution and deactivation serialization ([PR #85](https://github.com/sunstriker2009/sun-oryva/pull/85), squash merge `d8c54811`): migration 016 snapshots the bound Keycloak subject, redemption locks the viewer row and rejects changed subjects. Five PR workflows passed on final implementation head `9bd556b5`, including schema validation and full-stack PostgreSQL/Keycloak E2E. Migration refuses outstanding unbound legacy challenges; actor-audited revocation is required first. No email delivery, credential enrollment or activation. Post-merge main CI is tracked separately.
- [ ] Password-change and account recovery policies, audit events, API error contracts, and full lifecycle security E2E.
- [x] PostgreSQL-backed cross-replica management write quotas (migration 013, HTTP concurrency, 429 and outage-503 E2E; [PR #75](https://github.com/sunstriker2009/sun-oryva/pull/75), five workflows passed on implementation commit `e8f0e462` before merge). Edge, login, invitation and password-recovery quotas remain outstanding.
- [x] Process-local management write throttling with authenticated-subject partitioning and HTTP tests ([PR #71](https://github.com/sunstriker2009/sun-oryva/pull/71), verified).
- [ ] Production Keycloak permissions, operational migrations, threat review, release gates and deployment runbooks.

The M4 ledger records partial backend progress; it does **not** mean ORYVA-024 through ORYVA-026 are complete.

## M5 — consumer integration
- [ ] ORYVA-027 Reusable frontend/backend package releases.
- [ ] ORYVA-028 MarketPilot AI integration and deployment hardening.

**Security invariants:** exactly one active master per deployment; only the master creates admins; master/admin manage viewers; viewers are read-only. Database and validated token subject must match for active-master operations. CI-only password grants and HTTP discovery must never be enabled in production.
