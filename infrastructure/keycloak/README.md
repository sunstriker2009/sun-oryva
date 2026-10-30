# ORYVA development realm

The `oryva` realm is imported into the **local development** Keycloak instance on initial database creation. It defines the `master`, `admin` and `viewer` role names but **does not** create users, clients or secrets.

## Important boundaries

- A realm role named `master` does **not** enforce the one-master invariant. That must be enforced by an idempotent, concurrency-safe ORYVA management bootstrap service and verified with integration tests.
- Never expose the Keycloak infrastructure bootstrap admin account as an application master.
- Registration is disabled; email verification and brute-force protection are enabled. Email delivery and recovery policies are not configured.
- No application client is registered. OIDC client configuration, PKCE, redirects, service credentials, sessions, MFA, and production security policy are future work.
- Import is an **initialization** operation; Keycloak does not overwrite an existing realm on subsequent restarts. To change an existing realm, use an explicitly reviewed migration/admin operation.
- Do not use this development import in production without hardening, secrets management, TLS, and independent security review.
