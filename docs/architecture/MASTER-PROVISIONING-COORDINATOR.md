# Master provisioning coordinator — phase 1

**Status:** Preparation only; no credentials, role grants, or activation.

`PrepareAsync` acquires the PostgreSQL session lock, creates/reads the singleton reservation, and reconciles a disabled Keycloak identity bearing a deterministic deployment ownership marker. It refuses existing unmarked, mismatched or enabled identities. It also refuses preparation if any direct master role member exists.

**Fail-closed ambiguity:** If the Keycloak create request times out or returns an uncertain error, this method propagates the error without retrying the POST. The operator must rerun preparation, which re-queries the identity and verifies ownership. A stable ownership marker is correlation metadata, not cryptographic proof.

**Not production-ready:** No fencing for lock loss; no service-account permission policy; no credentials; no master role grant; no enablement; no PostgreSQL activation; no runtime identity authorization. An active database reservation returns an informational result and does not revalidate Keycloak drift. Do not expose this coordinator as an unauthenticated API.
