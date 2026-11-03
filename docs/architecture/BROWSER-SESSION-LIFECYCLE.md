# Internal browser-secret rotation and revocation (migration 023)

**Status:** opt-in internal backend foundation only. No public route, session cookie issuance, browser authentication, independent Keycloak email verification, credential enrollment or account activation is provided.

## Contract

`ViewerInvitationBrowserExchangeStore.RotateAsync(viewerId, browserSecret)` atomically replaces the SHA-256 digest of a live, viewer-bound, five-minute browser secret. The returned fresh 256-bit bearer is suppressed from JSON and `ToString()`; neither the new bearer nor the previous bearer is stored in PostgreSQL. The original `created_at`, `expires_at`, session UUID and challenge binding remain unchanged: rotation **never extends TTL**. PostgreSQL conditional updates guarantee that concurrent holders of the previous bearer have at most one winner. A failed audit insert rolls back the digest update.

`RevokeAsync(viewerId, browserSecret)` atomically marks the matching live session revoked, and writes the corresponding audit event in the same transaction. Repeated revocations, stale bearers, malformed secrets, expired sessions and wrong-viewer attempts are generic denials. Both operations take a viewer lock before updating the session, then revalidate the challenge consumption/revocation, exact Keycloak subject snapshot, unchanged email and database `role_assigned` state. They **do not** contact Keycloak or grant credential or activation authority.

Migration `023_browser_session_lifecycle_audit.sql` creates append-only `rotated` and `revoked` events, recording only opaque session/viewer UUIDs and database timestamps. An immutable trigger rejects UPDATE/DELETE, and no token, digest, email, IP or Keycloak subject is recorded. Audit rows deliberately do not reference browser sessions by FK so security evidence can survive controlled session purging. Runtime database privileges must be minimized and audit retention and tamper-evident offsite export must be reviewed for production.

## Security and operational gates

- Apply migrations 020, 021, 022 and 023 in order. The new store methods require migration 023; no production API registration changes.
- Do not treat `IsLiveAsync`, `RotateAsync` or `RevokeAsync` as authentication or password-write authorization. The future credential completion must independently verify email ownership and exact Keycloak disabled identity, serialize state transitions, and reconcile ambiguous Keycloak outcomes.
- Before HTTP exposure, implement an HttpOnly/Secure/host-only/SameSite cookie boundary with CSRF/origin validation, trusted-proxy review, distributed source-IP/global and viewer throttling, cookie replacement/clearing, no-cache responses and browser E2E. Do not place bearer secrets in URLs, logs or analytics.
- A stolen bearer can still win a rotation race. Rotation is not device binding, MFA or email verification. Reissue, identity changes, expiry and revocation must remain irreversible. Monitor generic denied attempts without logging bearer material.
- Final production gates include least-privilege PostgreSQL and Keycloak, production SMTP monitoring, recovery and password-change policies, audit retention, full browser/Keycloak security E2E and release validation.

## Validation

The isolated PostgreSQL integration test extends `Sun.Security.InvitationExchange.E2E` with 16 concurrent rotations and 16 revocations, replay and wrong-viewer denial, fixed expiry, JSON redaction, transactional audit-failure rollback, reissue invalidation and append-only event counts. The schema workflow applies migration 023 twice and rejects invalid events, UPDATE and DELETE. The full-stack workflow provisions the migration before executing the PostgreSQL security E2E.

**Do not mark the milestone verified until the final PR-head workflows pass.** Passing this internal test does not complete public browser enrollment or backend v1.
