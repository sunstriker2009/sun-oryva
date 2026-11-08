# HTTP cookie fixed-expiry regression

The guarded PostgreSQL/TestServer integration suite now checks that both the
first replacement cookie and the winner of a 16-way concurrent rotation carry
a positive Max-Age no greater than five minutes and no longer than the original
persisted browser-session expiry (allowing one second for wall-clock rounding).

The original PostgreSQL session expiration must not be extended by rotation.
The cookie is an untrusted transport bearer, not a Keycloak credential or proof
of email ownership. The suite continues to assert stale-bearer replay denial,
single-winner rotation and revocation, CSRF/origin rejection, and unchanged
viewer `role_assigned` state.

## Scope and limitations

This is a regression test for **cookie expiration bounds**, not a guarantee of
recovery after a committed database rotation whose HTTP response is lost.
Such a failure can strand the browser without its replacement bearer until
the original short-lived session expires. Recovery must use a separately
reviewed fresh invitation/email-proof ceremony, not an endpoint that reissues
a bearer based only on a stale cookie or viewer ID.

No production endpoint, password change, verified-email claim, activation,
SMTP dispatch or deployment is introduced. This PR is pending CI verification.
