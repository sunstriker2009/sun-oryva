# Guarded master role grant

`MasterProvisioningCoordinator.AssignPreparedMasterRoleAsync` acquires the PostgreSQL advisory lease, reads the singleton reservation, finds the candidate by exact username, and evaluates `MasterRoleAssignmentPolicy`.

- `Reject`: throw without attempting a grant.
- `Eligible`: call Keycloak's master role mapping transport once.
- `AlreadyAssigned`: do not repeat the POST; verify postcondition.

In all nonrejected cases, re-read direct master membership and require exactly the expected **disabled** subject. The operation does not enable the identity or activate the PostgreSQL reservation.

## Limitations and required follow-up

The advisory lock is not fenced against session loss; an external Keycloak administrator can mutate roles concurrently. Direct membership is not effective membership through composite roles/groups. HTTP ambiguity must be reconciled by rerunning after checking remote state. Role mapping should be tested against a real Keycloak instance, including retries and conflict scenarios, before deployment. Restrict service-account privileges and disable HTTP redirects for token-bearing requests. Runtime authorization must bind the token subject to the PostgreSQL active master subject.
