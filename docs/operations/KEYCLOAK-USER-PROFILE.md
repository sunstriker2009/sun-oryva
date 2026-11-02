# Keycloak ownership-profile deployment gate

ORYVA uses two Keycloak user attributes to prove that a candidate belongs to its own PostgreSQL reservation: `oryva.bootstrap.owner` for sole-master bootstrap and `oryva.provisioning.id` for guarded admin/viewer preparation. **Neither marker is an authentication credential or a substitute for PostgreSQL state and subject checks.** Both must be visible and editable only by Keycloak administrators, single-valued, and present in the *effective* realm user profile.

Keycloak 26.3.5 may not apply declarative user-profile components from an imported realm JSON. Therefore, validating the realm file alone is insufficient. This repository includes `infrastructure/keycloak/ensure_oryva_user_profile.py`, which reads the effective profile through Keycloak's Admin REST API. The default mode is **read-only**; `--apply` explicitly adds only missing reserved attributes. Existing attributes with unsafe permissions, duplicates or incompatible multiplicity are rejected rather than silently rewritten. The tool re-reads Keycloak after an update and verifies both markers.

## Operator procedure (staging first)

1. Provision the Keycloak realm and restrict access to the Keycloak management API. Use a short-lived token authorized to read and update the realm user profile. Validate the exact Keycloak privileges in staging; do not grant broad admin rights to the ORYVA runtime service account merely to perform this one-time deployment step.
2. Supply `ORYVA_KEYCLOAK_URL` (HTTPS origin), `ORYVA_KEYCLOAK_REALM=oryva`, and `ORYVA_KEYCLOAK_ADMIN_TOKEN` through the deployment secret mechanism. Never place the token in source control, shell history, CI output or command-line arguments. HTTP is permitted by the script only for localhost test instances.
3. Run `python infrastructure/keycloak/ensure_oryva_user_profile.py` to check the effective profile. If attributes are missing, review the intended change and run `python infrastructure/keycloak/ensure_oryva_user_profile.py --apply` during an approved change window. Run the read-only check again.
4. Verify that a newly created **disabled, unprivileged staging** identity can persist and return the exact marker, then remove that test identity. The isolated CI test exercises this with both markers. Do not use a real user or activate a production account as a smoke test.
5. Only after the check passes, enable guarded provisioning endpoints and apply database migrations in documented order. Continue to enforce exact ownership marker, subject, role exclusivity and PostgreSQL lifecycle state on every privileged transition.

If the check fails on an existing unsafe attribute, **stop** and investigate the current profile and affected users. The tool will not overwrite it. A successful check does not establish least-privilege runtime Keycloak service-account permissions, invitation safety, email delivery, account activation readiness or production release approval; those remain separate gates.

## Automated evidence

The `master-bootstrap-e2e` workflow runs `tests/integration/keycloak_user_profile_e2e.py` against an isolated Keycloak 26.3.5 instance before account provisioning tests. It applies the profile, checks idempotency, verifies that user-visible and duplicate reserved attributes fail closed, and round-trips both markers on a disabled throwaway identity. Test admin credentials are isolated to CI. The test never enables the probe identity, assigns roles, sends mail or deploys to production.
