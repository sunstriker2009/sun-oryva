# ORYVA viewer invitation challenge foundation (backend v1)

**Status:** Internal database primitives and isolated loopback Mailpit SMTP handoff only. **No invitation, redemption or enrollment HTTP endpoint is exposed.** No production SMTP delivery, browser ceremony, password-setting, Keycloak email verification, user enablement or production rollout is implemented.

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
| Stolen link / referrer leakage | No public HTTP route or production mailer exists | One-time exchange into a short-lived, HttpOnly, Secure, SameSite browser session; no bearer token in telemetry |
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

## Accidental JSON response disclosure guard

The internal `ViewerInvitationIssue.Token` is excluded from ASP.NET Core's default `System.Text.Json` response contract (`[JsonIgnore]`) and data-contract serialization (`[IgnoreDataMember]`). `ToString()` also redacts the token. PostgreSQL integration E2E tests exercise direct, object-typed, web-default and nested JSON serialization.

This is defense in depth, **not permission to return the issue object from an HTTP endpoint** or to log arbitrary object graphs. The plaintext token still exists transiently in memory and may be accessed by trusted code; custom serializers and explicit property access require separate review. A durable encrypted delivery outbox, SMTP transport, verified browser ceremony, credential enrollment and activation are **not implemented**.

## Encrypted, transactional delivery outbox foundation (migration 017)

`ViewerInvitationChallengeStore.IssueQueuedAsync` is an **internal-only** path
that returns a metadata-only receipt. The generated 256-bit bearer token is
encrypted using AES-256-GCM before being stored in
`oryva.viewer_invitation_outbox`. Its challenge, append-only issuance audit
and encrypted envelope are committed in one PostgreSQL transaction. If the
outbox insert or audit fails, issuance and any previous challenge revocation
roll back. The older `IssueAsync` method remains internal/test-facing and
must **not** be wired to an HTTP endpoint.

The key is supplied by a trusted runtime secret manager, never persisted in
the outbox, migrations or repository. Each envelope includes a random 96-bit
nonce, 128-bit authentication tag and non-secret key identifier. AEAD
associated data binds the challenge ID, viewer ID, recipient email snapshot
and key ID. Decryption rejects wrong keys, changed identities and tampering.
Key rotation must retain the matching previous key until all pending
envelopes using it have been cancelled or expired and securely purged.

Reissuing a challenge cancels previous pending outbox rows within the same
transaction; successful one-time consumption cancels the pending row too.
The database currently permits only `pending` and `cancelled` states.
At migration 017 there was **no SMTP sender, worker lease, retry, sent status or delivery claim**. Migrations 018–019 add leasing and isolated Mailpit handoff; no production dispatcher exists.
The ciphertext must never be treated as a deliverable invitation without a
future worker that locks the row, revalidates the live challenge, subject,
recipient and expiry at handoff, implements idempotent retries, redacts logs,
and safely handles revocation races. An email send cannot be atomically
committed with a PostgreSQL transaction, so delivery remains an at-least-once
operation requiring an explicit duplicate/retry policy.

Migration 017 must be applied after 016 and is tested for idempotence,
ciphertext shape, key identifier validation and cancellation constraints.
The isolated PostgreSQL E2E covers AEAD tampering, identity binding,
reissue/consumption cancellation and simulated outbox-insertion failure.
No browser enrollment, email ownership proof, credential change, Keycloak
activation or production delivery is authorized by this foundation.

## Fenced claim/retry foundation (migration 018)

The internal `ViewerInvitationOutboxLeaseStore` implements PostgreSQL
`FOR UPDATE SKIP LOCKED` claiming, one-minute leases with fresh UUID fencing
identifiers, a 20-second retry delay, five-attempt cap and invalid/expired
delivery cancellation. Claim eligibility requires an unconsumed, unrevoked,
unexpired challenge and an unchanged, role-assigned viewer with the original
Keycloak subject and recipient email. Reissue and token consumption now
cancel both pending **and leased** deliveries and clear lease identifiers.
The isolated PostgreSQL E2E covers twelve concurrent claimants, wrong/stale and expired
lease fencing, retry delay, cancellation after reissue, expiry, subject and
recipient substitution, and exhausted attempts. Migration 018 must precede the matching
application version and is applied twice in schema CI.

**Migration 018 alone has no SMTP sender or completion acknowledgment.** Migration 019 adds isolated loopback Mailpit handoff and relay-acceptance auditing, not production delivery. A claim is not a
delivery, and an expired lease must not be used to send. A future mailer
must revalidate under a transaction-held row lock at the actual SMTP handoff,
avoid logging plaintext bearer material, and handle ambiguous SMTP responses
as at-least-once delivery. A 60-second lease alone does not serialize a
remote SMTP send with revocation; it is NOT permission to send mail.
Browser URL/session design, verified email ownership, credential enrollment,
Keycloak activation and production least-privilege grants remain blocked.

## Transaction-held isolated SMTP handoff (migration 019)

The internal `ViewerInvitationSmtpHandoff` now rechecks the exact lease, 15-second
minimum lease/challenge lifetime, unchanged recipient and Keycloak subject,
viewer role-assigned state, revocation and consumption while holding a shared
viewer lock plus challenge/outbox write locks **through SMTP acceptance**. A
10-second bounded transport attempt prevents unbounded normal network waits.
Only after the relay accepts SMTP DATA does the transaction mark the outbox
`sent` and append a separate immutable `smtp_accepted` audit event. The
receipt means relay acceptance, **not recipient inbox delivery, email proof,
or account activation**. Stale leases cannot send; a concurrent reissue or
deactivation waits for the in-flight handoff transaction and subsequently
revokes or disables the invitation.

The only supplied SMTP adapter is `LoopbackMailpitInvitationTransport`, which
rejects non-loopback destinations and is exercised against a local CI Mailpit
container. **No production SMTP transport or automatic dispatcher is enabled.**
SMTP acceptance and PostgreSQL commit are not atomic: if SMTP accepts a message
but the transaction fails, retries can deliver duplicate emails. A single-use,
expiring challenge remains the authoritative replay defense. Errors from
untrusted transports are redacted, and no bearer appears in database audit.
Migration 019 is idempotence-checked in schema CI; PostgreSQL/Mailpit E2E
covers wrong-lease rejection, single acceptance, immutable audit, reissue,
redacted ambiguous failure and retry. Production TLS/SMTP credentials, safe
link/session design, browser email proof, Keycloak credential enrollment,
rate limits and release review remain blocked.

**Verification:** [PR #90](https://github.com/sunstriker2009/sun-oryva/pull/90) was squash-merged as `716d12b6` after all five workflows passed on final head `793b8ce6`, including schema validation and PostgreSQL/Mailpit full-stack E2E. Post-merge main CI is separately tracked; production SMTP, credential enrollment and activation remain blocked.

## Explicit single-iteration Mailpit dispatcher (verified PR #92)

`ViewerInvitationDispatchOnce` composes the fenced PostgreSQL lease store
with the transaction-held SMTP handoff. It is **not registered as a hosted
service** and has no automatic schedule, production SMTP adapter, HTTP route
or externally configured email destination. The only supplied adapter remains
the explicit-loopback Mailpit sink. Each invocation sweeps invalid invitations,
claims at most one eligible outbox row and performs the live, locked SMTP
handoff. A transport failure is converted into a redacted, typed exception;
the dispatcher schedules a 20-second fenced retry, respecting the existing
five-attempt limit. It never returns a bearer, recipient or SMTP transcript.

The return value `RelayAccepted` is **not** inbox delivery, ownership proof,
enrollment or Keycloak activation. Database failures propagate rather than
being disguised as transport failures. An ambiguous relay acceptance followed
by a database failure can still lead to a duplicate message on a later lease
reclaim; the one-time expiring challenge remains authoritative. The isolated
PostgreSQL/Mailpit E2E exercises concurrent invocations, exactly one relay
acceptance, transport failure with delayed retry, and deactivation sweep.
No external email is sent. A future production dispatcher requires a separately
reviewed TLS/authenticated SMTP implementation, secrets management, bounded
scheduling, monitoring, abuse quotas, and the browser ownership ceremony.

**Verification:** [PR #92](https://github.com/sunstriker2009/sun-oryva/pull/92) was squash-merged as `3b831ad9` after all four applicable PR workflows passed on final head `71d728f3`, including real PostgreSQL/Mailpit E2E. Post-merge main CI is not independently verified. No production delivery or enrollment was enabled.
