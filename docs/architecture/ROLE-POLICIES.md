# ORYVA role policies — M3 foundation

The JWT bearer middleware verifies issuer, audience, signature, lifetime and RS256 before deriving internal `oryva_realm_role` claims from the validated Keycloak realm-access role list. Incoming internal-role claims are rejected. Client roles are not trusted.

| Operation | Required policy |
| --- | --- |
| Master-only account/administrator creation | `Oryva.ActiveMaster` (validated master role **and** active PostgreSQL subject) |
| Admin operations | `Oryva.Admin` (validated admin realm role) |
| Read-only viewer operations | `Oryva.Viewer` (validated viewer or admin realm role) |

These are intentionally **not** hierarchical for the master: the master role alone does not satisfy admin/viewer policies, and admin never satisfies active-master. Endpoints needing master access alongside admin/viewer access must compose a separately reviewed policy with an active-master database check; do not add `master` to an ordinary role list.

This PR adds policy registration and trusted realm-role mapping, not user-management endpoints. Production role permissions, disabled-account revocation behavior, and end-to-end role matrix tests remain to be implemented. A JWT may remain valid until expiry after account deactivation unless additional revocation checks are added.
