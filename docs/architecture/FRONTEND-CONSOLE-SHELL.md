# ORYVA frontend console shell (initial)

The `@sun-security/console` Next.js app supplies a responsive, keyboard-accessible
public shell, metadata and explicit integration status. It deliberately does
**not** display a simulated login form or expose management endpoints. No
browser-supplied role or session object can unlock administrative routes.

Run `pnpm install --no-frozen-lockfile` and `pnpm --filter @sun-security/console dev`.
The CI frontend job must build the Next.js app and run its boundary test.

## Required before admin UI

1. Vetted OIDC Authorization Code + PKCE library with discovery, state,
   nonce and callback validation.
2. Server-owned session storage, Secure HttpOnly SameSite cookies, CSRF
   protection, logout revocation and explicit trusted-proxy configuration.
3. A server-side current-principal endpoint that validates Keycloak tokens
   and the ORYVA database account state. UI role capabilities remain UX only.
4. Protected server routes, authorization-negative integration tests,
   browser accessibility tests and session-expiration E2E.

No production login, password recovery, enrollment, external SMTP or
unverified-account activation is enabled by this shell.
