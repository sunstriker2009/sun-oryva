# Sun.Security.Bootstrap

**Foundation only; not a working Keycloak bootstrap.**

`MasterReservationStore` uses PostgreSQL's singleton primary key and row locking to create a durable `pending` reservation and activate a *previously verified* Keycloak subject. The API deliberately does not create users, assign roles, handle secrets or claim that a subject is verified. Callers must not expose `ActivateVerifiedAsync` as a public endpoint.

Initialize the ORYVA schema using `infrastructure/postgres/001_master_bootstrap.sql` before calling the store. Create and dispose a singleton `NpgsqlDataSource` in the application's DI container; inject it into the store.

Next: a privileged Keycloak management adapter, stable correlation IDs, reconciliation state machine, audit trail and concurrency/crash-recovery integration tests. Until those exist, **ORYVA-013 is incomplete**.
