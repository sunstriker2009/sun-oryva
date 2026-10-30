# Sole-master bootstrap — security design

**Status:** Schema and protocol design only. No master account is created by this change.

## Invariant and ownership

ORYVA owns a singleton reservation row in its PostgreSQL database, with `singleton_id = 1` enforced by both the primary key and a CHECK constraint. This guarantees **at most one** active master reservation in the database. The initial existence of a master is a separate provisioning requirement. Keycloak owns passwords, credentials, authentication and user sessions. The Keycloak bootstrap administrator is never the ORYVA master.

## Planned provisioning protocol

1. On startup, a privileged bootstrap component reads a one-time bootstrap secret from an external secret manager/environment, never from source control. Missing or placeholder secrets must fail closed.
2. Acquire a PostgreSQL transaction-scoped advisory lock using a documented stable lock key; read the singleton row under the same transaction. If already active, perform no provisioning.
3. If absent, insert a `pending` reservation and commit. The reservation survives a process crash. Do not create a second row or master.
4. Provision a **disabled**, uniquely identified Keycloak user through a restricted management client. Credentials are set through Keycloak's secure API, never stored in PostgreSQL or logged. Use a stable external correlation identifier to reconcile retries.
5. Reconcile any `pending` reservation against Keycloak on restart, and only activate the reservation after the matching Keycloak user and role assignment have been verified. Use the database lock/transaction to serialize activation.
6. Enable the Keycloak user only after the active reservation is durable and consistent; a crash during enablement must be safely retryable. The bootstrap must reject conflicting master role assignments and any ambiguous remote state.
7. Remove the initial bootstrap secret from the runtime configuration after successful provisioning; password changes use an authenticated Keycloak flow. Require MFA and recovery design before production.

**Cross-system consistency:** PostgreSQL and Keycloak cannot participate in a shared ACID transaction. A durable pending state plus reconciliation is required. The implementation must never infer that a successful remote API call implies the database transaction committed.

## Threats and required tests

- Concurrent service startup across multiple nodes; verify one reservation and one matching Keycloak user.
- Crash after pending insert, remote user creation, role assignment, activation and enablement; verify deterministic recovery.
- API timeouts, stale sessions, duplicate usernames, revoked bootstrap credentials, compromised or missing secrets.
- Unauthorized admin attempts to create a master or another admin.
- Manual Keycloak role changes outside ORYVA: periodic reconciliation must detect and alert on multiple masters, not silently pick one.
- No passwords, access tokens, recovery codes or raw secrets in logs or database.

## Implementation acceptance gate

This design is **not** a functioning bootstrap service. ORYVA-013 remains pending until a .NET 10 implementation, PostgreSQL migrations, Keycloak client, integration tests (including multi-instance and crash recovery), audit trail and operator runbook are delivered and verified.
