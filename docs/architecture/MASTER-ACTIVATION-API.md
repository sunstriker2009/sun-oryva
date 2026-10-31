# Mandatory ownership verification for master activation

`MasterIdentityVerifier.VerifyAndActivateAsync(expectedUsername, deploymentIdentifier, cancellationToken)` is now the only activation verifier method. The legacy overload without a deployment identifier was removed.

The verifier checks that the exact Keycloak username resolves to an enabled identity with the expected deployment ownership marker, that the identity is the sole enabled direct `master` role member, and that any already-active database subject matches before recording activation.

**Not yet production-ready:** this verifier does not hold the provisioning lease, does not enable users, and cannot fence Keycloak administrative changes. Runtime authorization must check the active PostgreSQL subject and effective role membership. Integration tests must cover interruption, ownership drift and external role changes. The ownership marker is correlation metadata, not cryptographic authentication.
