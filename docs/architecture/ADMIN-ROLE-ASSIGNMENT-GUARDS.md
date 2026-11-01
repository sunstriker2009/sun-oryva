# M4 admin role assignment — required guardrails

The existing `POST /api/master/admins/prepare` endpoint creates a disabled Keycloak account, but it does **not** persist an ORYVA-owned provisioning record. Therefore **do not expose an admin role-assignment or activation endpoint yet**: checking only that a Keycloak user is disabled is insufficient, because an unrelated pre-existing disabled account could be promoted.

## Required sequence

1. Active master authenticates with a signed JWT and passes the PostgreSQL-backed `Oryva.ActiveMaster` policy.
2. Normalize and validate username/email; reserve a unique admin provisioning record in PostgreSQL with deployment identity, actor subject, intended role, target username, state, and timestamps.
3. Create a disabled Keycloak user with an ORYVA-owned provisioning marker. Reconcile retries by verifying the marker, username, email and Keycloak subject ID; never adopt unrelated users.
4. Under a per-provisioning-record lock, verify the Keycloak user is still disabled and has no conflicting ORYVA role; assign **only** the admin realm role.
5. Provision a secure credential/invitation without returning a password or credential in API responses. Enable only after all invariants are verified.
6. Persist an audit event for each transition, including denied attempts and recovery; do not log secrets or access tokens.
7. Handle Keycloak/DB partial failures through explicit pending/reconciliation states. Never infer success solely from a successful HTTP request when persistence fails.

## Security constraints

- Admin role assignment is **master-only**, never allowed for an admin or viewer.
- The target must be an ORYVA-owned disabled account, not merely any Keycloak account.
- A target with `master` or `viewer` role is rejected. Conflicting roles are rejected at JWT validation as a defense in depth.
- A successful role assignment does **not** imply account activation.
- Require least-privilege Keycloak management service credentials and audit all operations.
- Account disablement and role removal need an explicit token revocation/session invalidation strategy.
- Tests must cover unauthorized actors, mismatched ownership, pre-existing users, concurrent requests, partial failures and retry recovery.

**Current implementation:** disabled-account preparation only (PR #48). This design intentionally does not grant additional privileges.
