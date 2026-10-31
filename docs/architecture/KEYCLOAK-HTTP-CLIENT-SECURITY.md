# Keycloak management HTTP transport

Use `KeycloakHttpClientFactory.Create()` for the bootstrap management adapter. The handler disables automatic HTTP redirects and cookie persistence, reducing the risk of credential-bearing requests being redirected to unintended endpoints.

The factory is opt-in: dependency-injection registrations must explicitly use an equivalent redirect-disabled primary handler. This PR does **not** retrofit existing HTTP client registrations or claim that redirects are prevented for arbitrary injected clients.

Future hardening: enforce same-origin endpoints and HTTPS outside local development; avoid logging tokens, credentials and response bodies; add tests that a redirect response is never followed. Do not expose the management adapter directly to user-controlled HTTP routes.
