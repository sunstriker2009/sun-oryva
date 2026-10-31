# ORYVA master provisioning — ownership and recovery design

**Status:** Design and ownership-marker primitive only. No automatic master provisioning.

## Invariants

1. PostgreSQL holds one durable master reservation per isolated deployment.
2. Keycloak's `master` realm role must have exactly one enabled, verified member before PostgreSQL activation.
3. A bootstrap identity must carry an ORYVA-owned deployment marker; matching username alone is not proof of ownership.
4. Never take over an existing unmarked Keycloak account, even if the username matches.
5. Initial master password is provided through an environment/secret-manager secret, never checked into source control, logged or stored in PostgreSQL.
6. Role grants and account enablement are security-sensitive operations; fail closed on ambiguous outcomes.
7. No master account is authorized merely because it has the Keycloak role: ORYVA authorization must also match the active PostgreSQL subject.

## Planned coordinator state machine

- **Reserve:** acquire the PostgreSQL singleton, and a deployment-wide provisioning lock.
- **Discover:** locate the expected Keycloak username; reject existing unmarked or mismatched accounts.
- **Create disabled:** create a disabled identity with a stable ownership marker; if creation times out, re-query and verify marker rather than blindly retry.
- **Set initial secret:** use Keycloak credentials API over TLS; never log or persist password.
- **Assign role:** verify there are no other master members; assign only to the owned identity.
- **Enable:** enable account only after credential and role verification.
- **Verify:** re-query Keycloak identity, ownership marker, enabled state, role membership and immutable subject ID.
- **Activate:** atomically persist the verified subject in PostgreSQL.
- **Reconcile:** on restart, resume only from provably owned states; otherwise stop and require operator intervention.

## Recovery matrix

| Interruption | Safe action |
| --- | --- |
| Before identity creation | Retry reservation and discovery |
| Creation succeeded but response lost | Re-query username and verify marker |
| Password update response lost | Re-apply initial secret only while identity remains disabled and bootstrap pending; never overwrite a changed password on an active master |
| Role assignment uncertain | Re-query full membership and ownership before retry |
| Enabled but PostgreSQL pending | Disable access at ORYVA authorization boundary; verify identity and role, then activate |
| PostgreSQL active but Keycloak drift | Deny privileged authorization and alert; do not auto-create replacement master |

## Security decisions required before enabling provisioning

- Implement Keycloak custom attribute ownership verification and least-privilege service account.
- Use a cross-process lock for all provisioning steps, not just row-level reservation.
- Add an authorization-time PostgreSQL subject check.
- Add Keycloak integration tests for interrupted operations, concurrency and role drift.
- Require explicit security review for password and role-grant changes.

The ownership marker is **not a credential or cryptographic proof of authority**. It is a deterministic correlation identifier; only a trusted provisioning service with tightly scoped Keycloak permissions may set it. Keep deployment identifiers confidential if they reveal sensitive topology.
