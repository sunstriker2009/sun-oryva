# Keycloak master role mapping transport

`KeycloakManagementClient.AddMasterRoleMappingAsync` resolves the realm-level `master` role representation and posts it to the intended subject's realm role-mapping endpoint.

**This is a low-level privileged transport operation, not an authorization boundary.** It must not be called from HTTP endpoints or other untrusted code. A future coordinator must hold the provisioning lock, check a pending reservation, verify the disabled candidate's ownership marker, run `MasterRoleAssignmentPolicy`, and re-read role membership after the POST.

No account enablement or database activation is performed.

## Security review and testing

- Verify the service account is restricted to the minimum required Keycloak admin permissions.
- Add Keycloak-backed tests for role lookup, mapping, same-subject retries, conflict, timeout and partial failure.
- A PostgreSQL advisory lock is not a fencing token; it cannot prevent mutations by independent Keycloak administrators.
- Validate effective roles (including composite/group assignments) and the PostgreSQL subject at authorization time.
- Disable HTTP redirects for bearer-token requests and avoid logging authorization headers.
- Do not deploy the role mapping transport as a public API.
