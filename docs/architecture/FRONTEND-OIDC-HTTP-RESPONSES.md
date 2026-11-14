# OIDC HTTP response boundary

The server-only response helpers are a narrow bridge between the completed OIDC orchestration and future Next.js route handlers.

- Login: a no-store 302 to the configured provider authorization endpoint with a short-lived Secure/HttpOnly/SameSite=Lax browser-binding cookie.
- Callback: a no-store 303 to a fixed local path, always clearing the binding cookie and issuing an opaque session cookie only after verified authentication.
- Logout: a no-store 303 to the console root, expiring both cookies. The route MUST first revoke the session in PostgreSQL; clearing the browser cookie alone is insufficient.
- Fixed response security headers disable caching and referrer propagation; cookie serialization forbids Domain, unsafe characters and invalid lifetimes.

**Not yet enabled:** These pure server helpers do not register routes. The subsequent integration must verify trusted request origin, instantiate PostgreSQL stores with production TLS, rate-limit initiation, ensure callback GET-only semantics, reject unexpected forwarded headers, revoke sessions on logout, and connect the backend active-role resolver. Keycloak browser E2E remains mandatory.
