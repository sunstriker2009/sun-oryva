# ORYVA viewer invitation challenge foundation (backend v1)

**Status:** Internal database and service primitives only. **No invitation, redemption or enrollment HTTP endpoint is exposed.** No SMTP delivery, browser ceremony, password-setting, Keycloak email verification, user enablement or production rollout is implemented.

## Why a separate challenge is required

In isolated Keycloak 26.3.5 testing (PR #79), `execute-actions-email` rejected a disabled, unverified account. ORYVA must not temporarily enable an unverified account to use that native action link. The proposed future flow therefore separates email ownership proof from Keycloak credentials and the existing guarded viewer activation coordinator.

The internal `ViewerInvitationChallengeStore` supports a deliberately narrow first phase:

1. A **separately JWT-authorized** database-active master/admin requests issuance for a `role_assigned` viewer with a bound Keycloak subject. The store independently checks the exact issuer subject and active role in PostgreSQL and holds a shared issuer row lock through commit. No viewer, anonymous, stale or forged management subject may issue.
2. A PostgreSQL row lock serializes issuance. Reissue revokes any previous unconsumed challenge in the same transaction. A 256-bit CSPRNG token is returned in memory **only** to the caller; the database stores its SHA-256 digest, recipient email snapshot, issuer subject/role and 15-minute expiry.
3. A future independently reviewed, authenticated delivery and browser ceremony may present the token. `ConsumeAsync` records possession **once** with an atomic PostgreSQL update only while the viewer is still `role_assigned`, subject-bound, email-unchanged, unrevoked and unexpired.
4. Consumption **does not** mark Keycloak email verified, set a credential, change any ORYVA account state, assign a role or enable login. It is not an enrollment completion signal.

Migration 016 also snapshots the exact bound Keycloak subject at issuance. Redemption
takes a shared lock on the viewer row and requires the subject to match this
snapshot, preventing an invitation issued for one identity from being redeemed
after subject rebinding. This serializes redemption with database-first viewer
deactivation. Outstanding legacy challenges have no provable subject snapshot, so migration
016 **refuses to run** until they are explicitly revoked with attributable
audit. Only terminal challenges are backfilled when the viewer still has a
subject; migration also fails closed if an orphaned/unbound challenge cannot
be backfilled. This preflight is a deliberate operational release gate, not
automatic production cleanup. PostgreSQL E2E covers subject substitution and restoration; it does
**not** establish verified email ownership or a safe credential ceremony.

The recipient snapshot intentionally detects email changes after issuance. A digest-only database leak does not directly reveal the 256-bit token. `ViewerInvitationIssue.ToString()` redacts the token. The token must never appear in logs, URLs captured by telemetry, analytics, referrers or admin responses.

## Threat model and mandatory next gates

| Threat | Current control | Still required before endpoint |
|---|---|---|
| Token guessing / brute force | 256-bit random token, 15-minute expiry, digest-only storage | Distributed per-identity/IP rate limits, generic error responses, anomaly alerts |
| Replay / concurrent redemption | Single atomic conditional update; exactly one winner | Browser CSRF/session binding, completion ceremony and retry/recovery policy |
| Reissue races | PostgreSQL viewer row lock and unique outstanding challenge index | Delivery outbox and idempotent resend semantics |
| Wrong recipient / changed identity | Email snapshot and viewer state/subject checks | Verified email delivery, canonical address policy, Keycloak ownership recheck |
| Stolen link / referrer leakage | No HTTP route or mailer exists | One-time exchange into a short-lived, HttpOnly, Secure, SameSite browser session; no bearer token in telemetry |
| Account escalation | No role assignment, credential or activation code in this milestone; issuance now requires an active PostgreSQL master/admin subject under transaction lock | Validated signed JWT and exclusive realm role at future API boundary; Keycloak credential enrollment in disabled state, explicit verified-email proof, guarded activation and complete audit |
| Data retention / abuse | Challenge rows include issuer, expiry and terminal timestamps | Retention/cleanup policy, least-privilege database grants, append-only delivery and consumption audit |

**Do not** treat a consumed challenge as sufficient to call the activation endpoint. The existing activation readiness checks still require independently verified Keycloak email, credential and required actions. The separate browser credential enrollment protocol is unresolved and must be validated against real Keycloak with a local mail sink and browser-compatible E2E before exposing any public route.

## Issuer authorization hardening (verified PR #83)

Issuance uses a shared lock on the matching active master singleton or active admin provisioning row inside the same PostgreSQL transaction that revokes and creates challenges. An admin deactivation update cannot commit while an already-authorized issuance holds this lock; once deactivation commits, subsequent issuance is denied. Missing, mismatched, pending and deactivated actors fail closed before any challenge mutation. The PostgreSQL E2E seeds isolated test actors, tests forged subjects and role mismatches, and confirms denied issuance does not revoke an outstanding token.

This is defense in depth, **not** a public API or a replacement for JWT validation. The caller must authenticate and verify the exclusive master/admin realm role and token subject; the store accepts no unauthenticated public traffic. No email, Keycloak credential write or activation is added. [PR #83](https://github.com/sunstriker2009/sun-oryva/pull/83) passed all five PR workflows, including real PostgreSQL/Keycloak E2E, and was squash-merged as `937fd43f`. This does not unblock enrollment.

## Operations and validation

Apply `infrastructure/postgres/014_viewer_invitation_challenges.sql` after migration 013, before any future service that uses it. It is idempotent for a fresh or already-migrated schema; the schema-validation CI job applies it twice and checks digest format, issuer roles, maximum lifetime and outstanding-token uniqueness. The PostgreSQL E2E tests cover unauthorized issuance, recipient changes, state changes, expiry, reissue revocation, wrong-viewer tokens, replay and 16-way concurrent consumption.

Migration `015_viewer_invitation_audit.sql` introduces a separate append-only event ledger for challenge issuance, reissue revocation, and successful one-time token consumption. The store writes each event **in the same PostgreSQL transaction** as the corresponding challenge mutation; a failed audit insert rolls back the mutation. Issuance and revocation record the supplied master/admin actor, while consumption records no actor because token possession alone is not an authenticated identity. No token, digest, email or password is stored in the audit. Events have unique `(challenge_id, event_type)` keys and reject UPDATE/DELETE; they deliberately survive challenge retention and deletion without a foreign key. The isolated PostgreSQL E2E checks exactly-once concurrent consumption, actor attribution and rollback on audit conflict.

This event ledger is **not** proof of SMTP delivery, email ownership verification, credential enrollment, account activation, or a complete lifecycle security audit. The store now also enforces the issuer's current PostgreSQL active state and subject/role match under a shared row lock; the future caller must **still** validate the signed JWT, its subject and exclusive realm role before calling the store. PostgreSQL-only actor checks cannot authenticate a remote request. Production least-privilege database grants and retention policy remain outstanding. No production service currently calls this store. Before deployment, provision narrowly scoped database privileges and retention controls, define encrypted delivery/outbox handling, and run a threat review and security release gate. Never place real credentials, invitation tokens or email addresses in source control or CI logs.

**Invariant:** sole master creates admins; master/admin manage viewers; viewers remain read-only; only database-active and independently verified identities may authenticate. Nothing in this foundation changes those boundaries.
