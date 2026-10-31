# Master role assignment contract

Before a role grant, require a pending PostgreSQL master reservation, a held provisioning lease, and an exact Keycloak subject match for a disabled identity bearing the expected ownership marker.

A role membership check must permit only zero existing members (new grant) or exactly the same verified subject (idempotent recovery). Any different or multiple members fail closed. Recheck membership after the operation; never enable the user or activate PostgreSQL in this step.

The PostgreSQL advisory lock is not a fencing token. A lost session, external Keycloak admin mutation, group/composite role inheritance, or an ambiguous HTTP timeout can invalidate assumptions. The coordinator must stop privileged writes on lock loss and reconcile ambiguous outcomes. Runtime authorization must check the bound PostgreSQL subject, not merely a role claim.

## Required integration cases

- No member, owned disabled identity, pending reservation.
- Same subject already assigned; safe retry.
- Different or multiple members; reject.
- Enabled, unowned, or mismatched identity; reject.
- Active database reservation; reject.
- Ambiguous remote response; requery before retry.
- Lock loss and concurrent external mutation; fail closed.

**Status:** Security contract only. No privileged role grant is implemented by this change.
