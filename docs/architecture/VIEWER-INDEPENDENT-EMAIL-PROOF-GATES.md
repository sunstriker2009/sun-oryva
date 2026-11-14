# Independent viewer email-proof gate — implementation acceptance criteria

**Status:** security design gate only; no public endpoint or account activation is authorized. This is a prerequisite to implementing lost-response session recovery and viewer credential enrollment.

## Trust and authorization

- The browser's stale session cookie, CSRF token, viewer ID, email address, or operator assertion must never count as proof of email ownership.
- A challenge must be minted using a cryptographically secure random generator, stored only as a keyed digest, scoped to one reserved viewer and the exact disabled Keycloak subject, canonical email, and current provisioning generation.
- Deliver proof only to the independently reconciled reserved email through an approved, verified SMTP channel. Never return the proof to the requesting browser or include it in logs, audit records, traces or metrics.
- Do not set Keycloak `emailVerified`, credentials, or `enabled` on challenge issuance or consumption. These are separate, explicitly reviewed ceremonies.
- Master/admin/viewer privileges remain database-backed; only the sole master creates admins, and admins cannot create or elevate admins.

## Atomic PostgreSQL consumption

Within a transaction, lock the viewer reservation and challenge; verify digest in constant time, expiration, purpose, unconsumed state, attempt quota, unchanged Keycloak subject/email, disabled state and exact ownership markers. Mark proof consumed exactly once. Invalidate all prior browser sessions and outstanding invitations for the same viewer before establishing a fresh fixed-expiry session. Roll back every state change if any step fails. A second replica must observe the committed winner and deny replay.

Keycloak is external to PostgreSQL: perform a fresh reconciliation before the transaction and recheck relevant persisted generation/identity fields under lock. If external identity changes cannot be safely excluded between verification and commit, **fail closed**; do not claim atomicity across PostgreSQL and Keycloak. Any ambiguous Keycloak or SMTP response must not grant access.

## Public boundary and operational gate

No public recovery endpoint until HTTPS, trusted proxy allowlist, Host/Origin/Fetch Metadata, CSRF, IP/global quotas, SMTP relay verification, error redaction and audit/incident procedures have been reviewed and tested in the deployment topology. Return generic failures without account enumeration; do not reveal whether a challenge, account, or session exists.

## Required integration tests before merge of implementation

1. PostgreSQL/TestServer: expired, malformed, wrong-viewer, replayed and already-consumed proof deny with no session issuance or TTL extension.
2. 16+ concurrent requests across separate service instances: exactly one proof consumption/session reissue; all losing requests issue no bearer.
3. Changed reserved email, Keycloak subject, ownership marker, role or disabled state: deny; old challenge cannot be used after an identity generation change.
4. Lost rotation response: stale bearer cannot request or redeem recovery without a fresh independent proof.
5. SMTP unavailable, ambiguous delivery and transaction rollback: no proof disclosure, credential mutation, activation or session issuance.
6. Proxy-spoofed headers, cross-origin POST, invalid/duplicate CSRF cookies and rate-limit exhaustion: fail closed.
7. Audit and observability: no raw proof, session bearer, email delivery secret, password or credential appears in logs or append-only audit.
8. Explicit invariants: master singleton unchanged; admin creation remains master-only; viewer never acquires admin/master permissions.

## Release condition

Document the concrete implementation PRs, final-head CI checks, real PostgreSQL/Keycloak/Mailpit E2E results and post-merge checks separately. Do not mark backend v1 complete until credential enrollment, password recovery, production SMTP/proxy review and final security E2E have passed.
