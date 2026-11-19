# OUTPOST by Sun — Development handoff

**Prepared:** 2026-11-15 · **Repository:** `sunstriker2009/sun-outpost` · **SUN product:** SUN-C001

> **Read this first when resuming after a chat archive or memory cleanup.** This document is a snapshot, not a replacement for current GitHub state. Verify `main`, open PRs, required checks, scheduled automation status, and current documentation before modifying anything. Never treat the last PR number here as permanently current.

## Product and immutable design boundaries

OUTPOST by Sun — **Identity. Trust. Protection.** — is an independently deployable authentication, authorization and identity/security platform for SUN products. MarketPilot AI is the first planned consumer, not a dependency. Backend namespace `Sun.Security.*`; frontend package scope `@sun-security/*`. Current baseline: .NET 10+, ASP.NET Core, Keycloak 26.3.5, PostgreSQL 17, Next.js 15/React 19. Master is unique; only Master can create Admins; Master/Admin may manage Viewers subject to backend policy. Browser-supplied roles and decoded unverified claims never grant access. Follow canonical branding assets in `branding/assets/` and SUN repository governance.

## Verified snapshot (2026-11-15)

- PR **#150** (OIDC callback SameSite=Lax binding cookie) was verified merged.
- GitHub `main` subsequently included merged PRs **#160–#171**; at inspection its latest commit was `d81135e49` (`security: reject malformed OIDC session identity fields (#171)`). The GitHub open-PR query returned **no open PRs** at that instant. **This may change after this handoff.**
- Implemented frontend routes listed in `docs/roadmap/V1-AUTH-RELEASE-GATES.md`: `GET /api/auth/login`, `GET /auth/callback`, `POST /api/auth/logout`. They are gated by explicit server-side OIDC configuration.
- Frontend OIDC foundations include server-only discovery, PKCE/state/nonce, browser-bound single-use PostgreSQL transaction, AES-GCM sealed verifier/nonce, bounded code exchange, RS256 ID-token verification, callback orchestration, opaque PostgreSQL session hashes, cross-connection session tests, cookie and logout boundaries. Existing code and tests are the authority for exact behavior.
- **Crucial blocker:** `src/frontend/apps/console/lib/auth-boundary.ts` still implements `resolveServerAuthorization()` as `{ kind: "unavailable" }`. Protected console resources must remain denied until a trusted backend-backed resolver is integrated and tested.
- Backend foundations include Keycloak/JWT and database-backed active Master/Admin/Viewer policies, guarded provisioning/activation/deactivation, PostgreSQL concurrency/audit, and internal browser-invitation/session primitives. These do **not** prove complete public credential enrollment or production release readiness.
- Existing `README.md`, `MASTER-CHECKLIST.md` and `docs/roadmap/MILESTONES.md` contain older status dates; read them for detailed backend history, but do not infer that their older frontend status is current. The more recent `docs/roadmap/V1-AUTH-RELEASE-GATES.md` is the current release gate contract.

## Unfinished work — suggested order

1. **Trusted console authorization (blocking):** implement a server-only resolver that reads the opaque session, verifies issuer/subject, and obtains **current** active status and effective Master/Admin/Viewer role from trusted OUTPOST backend data on every privileged request. Explicitly deny malformed/unknown/ambiguous roles, inactive or deleted identities, revoked sessions and backend/database outages. Preserve separation of session identity from authorization. Test immediate role revocation and role transitions. Do not replace the fail-closed stub before the integration and negative tests exist.
2. **Real OIDC browser E2E (blocking):** exercise login → Keycloak redirect → callback → session → protected access → logout → re-login against actual Keycloak/PostgreSQL and a real browser. Include state, nonce, PKCE, signature, issuer, audience, expiry, replay, duplicate callback parameters, binding-cookie behavior, cross-origin logout, and backend outage failures. Verify the configured `SameSite=Lax` short-lived binding cookie on top-level callback GET.
3. **Credential/user lifecycle:** finish secure viewer invitation and independently verified email ownership, browser credential enrollment, password change/recovery, production-safe account activation and failure recovery. Review the internal opt-in browser components in the backend before exposing public enrollment endpoints. Master/Admin management UI remains to be completed.
4. **Security and operations:** review use of custom OIDC/RS256 code against a maintained protocol/Jose library; validate Keycloak least privilege, strict public-origin/proxy configuration, database migrations and TLS, encryption/HMAC key rotation, CSRF, admission quotas, session cleanup/retention, observability without secrets, recovery/rollback and production smoke tests.
5. **Release and integration:** complete management console, package/integration contracts, MarketPilot AI first-consumer integration, deployment documentation, release CI/negative-path gates and a release-readiness signoff. Do not claim v1 complete until every applicable release gate is verified.

## Source-of-truth reading order

1. `docs/roadmap/V1-AUTH-RELEASE-GATES.md` — **blocking** browser-auth release contract.
2. `src/frontend/apps/console/lib/auth-boundary.ts` — current protected-resource authorization gate.
3. `src/frontend/apps/console/app/` — actual Next.js route implementations.
4. `src/frontend/apps/console/lib/oidc-*.mjs`, `db/` and `tests/` — transaction/session and protocol code, migrations and tests.
5. `MASTER-CHECKLIST.md` and `docs/roadmap/MILESTONES.md` — backend milestone ledger (some summaries stale).
6. `docs/architecture/`, `docs/operations/`, `docs/adr/`, `README.md`, and SUN governance docs — deeper design, threat boundaries and policies.
7. GitHub PR history, branch protection and CI runs — latest merged implementation and actual test evidence.

## Development/approval rules

- Always inspect the **live** GitHub repository and PR/CI status first; don't assume a remembered status or a successful local test equals green CI.
- Implement cohesive changes on **feature branches**; open PRs. **No direct commits to `main`, no self-merging or bypassing branch protection; user approval is required before merging.**
- Prefer tests, fail-closed behavior and small auditable security changes; avoid enabling public authentication, account mutation or production secrets without appropriate gates.
- Keep GitHub Actions within the free quota: reuse existing jobs, batch coherent edits, avoid redundant CI reruns.
- Maintain a concise continuation summary with confirmed state, PR link, CI evidence, blockers, next action and explicit unknowns.
- A separate **OUTPOST Hourly Development** automation was created on 2026-11-14 (ID `Automation_5c08b6aefd908191bb88cae0816d8c6b`). Its **current** enabled/paused state and project/thread placement must be checked in ChatGPT automation settings; GitHub does not prove its status. The user's request was to continue hourly until completion or explicit stop. Archiving a conversation or sweeping memory is not, by itself, authorization to change or stop the automation.

## Restart prompt

> Resume OUTPOST by Sun (SUN-C001) from `docs/roadmap/DEVELOPMENT-HANDOFF.md`. Verify the current `main` commit, open PRs, CI, and release gates first. Identify the smallest highest-value unfinished security/feature milestone, implement it with tests on a feature branch and open a PR. Do not merge without approval. Preserve fail-closed authorization and report confirmed state versus unknowns. Update the handoff and milestone docs as work progresses.

**Snapshot limitations:** This note is based on inspected GitHub content, not a full local build or real browser/Keycloak deployment test. The release gates remain unverified unless newer CI or operational evidence explicitly proves them.
