# Ownership-aware master activation verification

`MasterIdentityVerifier.VerifyOwnedAndActivateAsync` verifies the expected deployment ownership marker on the Keycloak identity, requires an enabled identity and exactly one matching enabled direct `master` role member, then activates the PostgreSQL singleton for that subject.

The existing `VerifyAndActivateAsync` is retained for compatibility, but **does not check ownership**. Do not expose the legacy method to bootstrap entrypoints. The new method also does not acquire the PostgreSQL provisioning advisory lease; the trusted caller must coordinate external Keycloak mutations.

## Remaining work

- Keycloak account enablement must be separately guarded and tested.
- Both activation methods need authorization-boundary review and migration to a single fail-closed entrypoint.
- Add end-to-end tests for interruption between Keycloak enablement and PostgreSQL activation.
- Session advisory locks are not fencing tokens; check lease continuity and reconcile remote drift.
- Runtime master authorization must compare the authenticated subject with the active PostgreSQL master subject.
- Verify effective roles, not solely direct realm-role membership.
