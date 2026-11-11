# ORYVA frontend session presentation boundary

The reusable core package now defines a **display-only** session snapshot and
screen state model. Consumers must obtain the snapshot from a server endpoint
which validates a real authenticated session and current backend account state.
Never construct a session from unverified browser input, decoded JWT claims or
localStorage. No token, password, client secret or cookie is handled by this
package.

The application server must implement OIDC Authorization Code + PKCE with a
vetted library, exact issuer/audience/nonce/state checks, CSRF protection,
secure HttpOnly SameSite cookies, rotation and logout invalidation. The UI
should use the explicit anonymous, expired and unavailable states and must not
treat a service outage as authentication success.

`safeOryvaReturnPath` is a defense-in-depth helper for same-origin paths,
not a replacement for an application-specific redirect allowlist or
server-side callback validation. Reject arbitrary URLs at every redirect
boundary.

The existing backend remains provisionally frozen. Independent email proof,
enrollment, recovery, external SMTP and activation of unverified accounts
remain unavailable. This milestone does **not** implement login, logout,
session persistence, protected server routes or production authentication.
