# Master role assignment decision policy

`MasterRoleAssignmentPolicy.Evaluate` is a pure, side-effect-free preflight decision. It returns:

- `Eligible` only when the database reservation is pending, the candidate is disabled and ownership-verified, and no direct master role member exists.
- `AlreadyAssigned` only when exactly the same verified disabled candidate is the sole direct master role member.
- `Reject` for every other state, including an active reservation, missing or mismatched ownership marker, enabled candidate, different member or multiple members.

This is not a grant operation or authorization decision. It must be invoked inside the provisioning lease immediately before a privileged grant, followed by a fresh Keycloak membership check after the operation. Advisory locks do not fence external Keycloak administrators or network partitions. Effective membership through groups/composite roles remains an unresolved risk.

## Required follow-up

Add C# unit tests covering every branch, Keycloak-backed integration tests for role mapping and ambiguous HTTP failures, then wire the coordinator to the restricted management adapter under explicit security review. Do not enable account or activate PostgreSQL as part of role assignment.
