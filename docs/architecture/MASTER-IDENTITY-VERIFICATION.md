# Master identity verification gate (M1)

**Status:** Reconciliation/activation gate, not automatic master provisioning.

The verifier checks the expected username, enabled state, immutable Keycloak subject ID, and the **complete** Keycloak realm-role membership for `master` before activating the PostgreSQL singleton. It rejects missing identities, zero/multiple role members, disabled identities and conflicting subjects.

The caller must run this from a trusted bootstrap operation, not an unauthenticated endpoint. The adapter must have read access to role membership. Any Keycloak permission error fails closed.

## Known distributed-system limitation

Keycloak and PostgreSQL do not share a transaction. Role membership can change between verification and database activation. **Do not consider this sufficient for production sole-master enforcement.** The next stage must implement a single-writer provisioning coordinator, stable identity ownership, post-activation verification, drift detection, authorization-time subject checks, and failure recovery.

No user is created, password set, role granted, or account enabled by this gate. No credentials are stored in source control.
