# Master initial credentials (M1)

**Status:** Credential-setting operation only; role assignment and activation remain disabled.

The trusted coordinator method `SetPreparedInitialPasswordAsync` acquires the provisioning lock, verifies the PostgreSQL reservation is pending, checks there are no direct `master` role members, and validates that the target Keycloak identity is disabled and carries the expected deployment ownership marker. It then calls Keycloak's `reset-password` Admin REST endpoint.

## Operational safeguards

- Supply the initial password from a secret manager or an environment secret at runtime. Do not commit it, print it, persist it in PostgreSQL or pass it via an HTTP query parameter.
- At least 16 characters are required. Avoid logging request payloads or exceptions that could include credentials.
- Restrict the Keycloak service account to the minimum necessary privileges.
- Do not expose this coordinator through a public API.
- On a timeout, do not assume whether the password was changed. Reconcile while the account remains disabled and the bootstrap is pending.
- A compromised service-account credential or external Keycloak admin can bypass these application checks.

## Outstanding work

The current lock is not fenced against network partitions. A privileged role grant, enabling the account, authorization-time subject validation, password-change UI, credential rotation and end-to-end Keycloak tests are not implemented. The transport API is internal infrastructure code, not a public credential-management API.
