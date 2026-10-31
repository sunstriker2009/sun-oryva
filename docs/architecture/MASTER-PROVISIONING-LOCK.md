# Master provisioning cross-instance lock

**Status:** Implemented primitive, coordinator integration pending.

`MasterProvisioningLock` uses a fixed PostgreSQL session advisory-lock key and keeps a dedicated database connection open for the duration of a provisioning attempt. A second ORYVA instance sharing the same database receives no lease while the first holds it. Disposal clears the connection pool before closing the session to avoid retaining a session lock in the pool.

## Requirements for callers

- Acquire the lease **before** reservation discovery, Keycloak creation, credential changes, role assignment or activation.
- Keep the lease alive across the complete operation; dispose in a `finally` or `await using` scope.
- Never run provisioning if acquisition returns null.
- On database connectivity loss, **stop issuing Keycloak mutations**. A PostgreSQL session lock is not a fencing token; a second instance may acquire it while the original process is still running.
- Re-query identity ownership, role membership and database state after each uncertain remote outcome.
- Run the coordinator with one trusted service identity and restrict external Keycloak role mutations.

## Remaining risks

Session advisory locks do not make Keycloak and PostgreSQL transactional. Lock loss, administrator changes in Keycloak and delayed HTTP operations require explicit fencing/reconciliation safeguards. This primitive must not be described as complete sole-master enforcement.
