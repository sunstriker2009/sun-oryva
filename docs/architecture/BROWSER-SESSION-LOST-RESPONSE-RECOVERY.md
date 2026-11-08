# Browser-session post-commit response-loss recovery boundary

**Status:** proposed security contract; documentation only. No recovery endpoint is authorized by this document.

## Failure model

PostgreSQL can commit a browser-secret rotation while the HTTP response carrying the replacement Set-Cookie header is lost. The browser then holds a stale bearer, while the replacement digest is the only live credential. Neither an HTTP 200 from the server nor a database commit proves that the browser received the replacement.

**Fail closed:** a stale bearer must remain invalid. Do not retry rotation using the old bearer, expose the current bearer, reverse the digest update, or extend the original five-minute expiry. A viewer ID, CSRF token, existing cookie, email string, or an operator assertion is not independent identity proof.

## Proposed recovery contract (requires separate security review)

1. Return generic denial for stale, expired, revoked, wrong-viewer and malformed bearers; do not disclose whether a live replacement exists.
2. Recovery starts a **new**, independently verified email-ownership/invitation ceremony. Require a fresh, one-time, short-lived challenge delivered through an approved channel, with PostgreSQL atomic consumption, throttling, audit and exact disabled Keycloak subject/email reconciliation.
3. Reissue must invalidate all prior browser sessions and invitations for that viewer before any new session can be established. Keep the viewer disabled; do not set Keycloak emailVerified or credentials from an unverified browser session.
4. If the verified ceremony is not yet implemented or the SMTP/trusted-proxy operational gates are not satisfied, return a generic failure and require operator-assisted restart under an audited policy. Never silently recover from the stale cookie.
5. Treat Keycloak credential enrollment, activation and password recovery as distinct transactions with independent authorization and ambiguity reconciliation.

## Required validation before public exposure

- PostgreSQL/TestServer test: commit a rotation, discard the response, replay the original cookie and assert denial, no Set-Cookie replacement, no new session, no TTL extension and no role change.
- Concurrency test: losing rotation requests cannot recover the winner's bearer; a winner remains live only until the original expiry.
- Fresh invitation reissue test: old session and challenge are invalidated atomically, including across replicas; audit records contain no secrets.
- End-to-end negative cases: expired/replayed proof, changed email or Keycloak subject, disabled/activated identity mismatch, SMTP failure, proxy spoofing, CSRF/origin failures and interrupted transactions.
- Review recovery observability, rate limits, log redaction, audit retention, incident response and browser UX without creating an account-enumeration oracle.

This is not a promise of transparent recovery. A user may need a new verified invitation after a lost response. Until the independent proof ceremony is complete, backend v1 is **not** ready for public enrollment.
