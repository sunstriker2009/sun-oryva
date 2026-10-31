# Provisioning lock integration coverage

The PostgreSQL CI integration suite validates the advisory-lock protocol used by the .NET `MasterProvisioningLock`:

- Competing PostgreSQL sessions cannot acquire the same key concurrently.
- Explicit unlock permits another session to acquire.
- Closing the owning session releases the lock.
- Committing a transaction does not release a session-scoped lock.

**Limitations:** These tests exercise the PostgreSQL protocol, not the Npgsql lease implementation or a complete coordinator. They do not prove behavior during network partitions or that Keycloak mutations stop when the lock is lost. Add .NET integration tests and fencing/reconciliation tests before production provisioning.
