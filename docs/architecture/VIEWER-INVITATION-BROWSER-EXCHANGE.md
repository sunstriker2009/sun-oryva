# Internal invitation-to-browser exchange (migration 020)

**Status:** internal backend foundation only; not a public endpoint or a completed enrollment flow. Apply `infrastructure/postgres/020_viewer_invitation_browser_exchange.sql` after migration 019, before running the updated invitation issuance code.

## Contract

A 256-bit invitation bearer secret can be exchanged **once**, while it is still valid, for a different 256-bit, five-minute browser secret. The PostgreSQL transaction locks the viewer before updating the challenge, records the existing append-only `consumed` audit event, stores only the SHA-256 digest of the new secret, and cancels pending/leased SMTP deliveries. A failed insert or audit rolls everything back. Cross-replica races have one winner.

Both issuance and exchange enforce a subject-bound, `role_assigned` viewer and unchanged recipient email. Reissuing an invitation revokes any outstanding browser exchanges under the viewer lock. A PostgreSQL trigger also permanently revokes browser exchanges when the viewer's email, Keycloak subject or lifecycle state changes, **including when changed back**. Expiry is enforced against PostgreSQL time.

The returned `ViewerInvitationBrowserExchange` intentionally redacts the secret from JSON and `ToString()`. No secret or plaintext email is written to the browser session table. The internal `IsLiveAsync` method is **point-in-time inspection only** and MUST NOT be used as authentication, a password-write permission or an activation gate.

## Threat boundaries and unfinished work

- **Proof scope:** possession of an invitation code is not independent confirmation that Keycloak's email is verified. Neither exchange nor inspection sets `emailVerified`, writes a credential, enables an account, grants roles, or creates a Keycloak session.
- **No HTTP exposure:** before an exchange endpoint is added, implement a reviewed browser ceremony that avoids bearer tokens in URLs/referrers/analytics, uses short-lived `HttpOnly`, `Secure`, appropriate `SameSite` cookies, origin and CSRF checks, generic errors, strict host/origin allowlisting and distributed IP/identity throttling.
- **No automatic credential enrollment:** a future Keycloak password-write and email-verification ceremony must revalidate the exact owned disabled Keycloak subject, required actions, exclusive viewer role, email and current database state under appropriate locks. The inspection result is not a substitute for an atomic one-time completion gate or reconciliation after ambiguous Keycloak outcomes.
- **Session theft/replay:** the browser secret remains a bearer secret until a separately reviewed, single-use completion protocol is built. No production route may treat it as a login.
- **Operational controls:** provision migration 020 before deploying the new issuer; monitor failed exchanges without logging tokens or recipient PII, define retention/purge and recovery procedures, review database privileges and run real Keycloak + browser E2E before exposing the flow.

## Validation

`tests/integration/Sun.Security.InvitationExchange.E2E` runs against isolated PostgreSQL and covers malformed/cross-viewer input, exactly-one-winner concurrency, audit and insert rollback, JSON non-disclosure, digest-only storage, expiry, reissue invalidation, subject/email change-away-and-back revocation and unchanged viewer activation state. The schema-validation workflow applies migration 020 twice and checks fail-closed constraints.

**Not delivered:** browser HTTP/cookie endpoints, email ownership verification against Keycloak, credential enrollment, password recovery, activation, production SMTP integration or release readiness. See [disabled-account enrollment gate](../operations/KEYCLOAK-DISABLED-ENROLLMENT.md) and the [master checklist](../../MASTER-CHECKLIST.md).
