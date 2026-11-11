# ORYVA Next.js server-side access boundary

The console now contains protected server-rendered workspace, users, audit and
security routes. Every route invokes a server-side resource guard before
rendering. A session endpoint responds with no-store headers and HTTP 503
while authentication is not configured.

**Critical:** The default resolver intentionally returns `unavailable`. No
browser-supplied principal, cookie JSON, localStorage role or decoded JWT
is accepted as authorization. Even if a user guesses a protected URL, the
server redirects to integration status. The role capability function is
only useful after a trusted session resolver has been implemented.

The next milestone must integrate a vetted OIDC authorization-code + PKCE
library, verify issuer/audience/nonce/state, establish Secure HttpOnly
SameSite cookies, implement CSRF and logout revocation, and validate current
database account state on protected requests. Only then may the resolver
return `authorized`; comprehensive negative and full-stack E2E tests are
required before enabling administrative actions.

This is a **route security scaffold**, not functional sign-in or a
production-ready console. Backend v1 remains provisionally frozen and
unverified enrollment/recovery/activation stays disabled.
