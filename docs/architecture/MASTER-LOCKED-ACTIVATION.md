# Locked ownership-verified master activation

`MasterIdentityVerifier.VerifyAndActivateAsync(expectedUsername, deploymentIdentifier)` now acquires the deployment-wide PostgreSQL advisory lease before reading reservation state, Keycloak identity and role membership. The lease is retained through `ActivateVerifiedAsync` and disposed afterward.

The verifier requires an enabled identity with the expected deployment ownership marker, exactly one enabled direct realm `master` role member matching its subject ID, and consistency with an existing active database reservation. PostgreSQL activation is idempotent only for the same subject.

**Limitations:** the advisory lease is session-scoped and not a fencing token; unexpected connection loss during a remote call is not detected before the subsequent database write. Independent Keycloak administrative mutations and composite/group-derived roles are outside the direct-role membership check. Runtime authorization must validate the active database subject. Test real lock contention and lost-session behavior before production deployment.

**API compatibility:** constructor now requires `MasterProvisioningLock`. This intentionally prevents constructing the verifier without a provisioning lease dependency.
