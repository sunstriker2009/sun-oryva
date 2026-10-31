# Guarded master account enablement

`MasterProvisioningCoordinator.EnablePreparedMasterAsync(username, deploymentIdentifier)` holds the PostgreSQL provisioning advisory lease, requires an unbound pending reservation, verifies the exact Keycloak username and deployment ownership marker, and requires exactly one direct master role member matching that subject.

Only a disabled owned candidate with matching disabled role membership is enabled via the Keycloak Admin API. If a previous enablement succeeded but its response was lost, the method can reconcile an already-enabled candidate, provided identity ownership and sole role membership remain valid. It rereads both the identity and role membership after the operation.

**Security boundaries:** This does not activate the PostgreSQL master reservation, verify that a password was configured, guarantee that the advisory-lock session survived a network partition, or prevent independent Keycloak administrators from modifying roles. The enabled identity must not receive application master authorization until PostgreSQL active-subject binding and effective-role checks are enforced. Never expose this low-level operation to untrusted callers.

**Required follow-up tests:** real Keycloak enablement, ownership drift, wrong subject, multiple role members, ambiguous HTTP failure and restart recovery. A separate lock-guarded activation coordinator should replace direct verifier calls.
