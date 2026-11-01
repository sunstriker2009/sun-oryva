# ORYVA integration tests

GitHub Actions runs isolated PostgreSQL 17 and Keycloak 26.3.5 services.
The workflow applies migrations in order before running the .NET test runners.

- `Sun.Security.Bootstrap.E2E`: sole-master bootstrap, signed Keycloak JWT
  verification and active-master/admin/viewer HTTP policy boundaries.
- `Sun.Security.AdminProvisioning.E2E`: real Keycloak and PostgreSQL admin
  reservation, recovery, role assignment, activation, deactivation and audit.
- `Sun.Security.ViewerAuthorization.E2E`: PostgreSQL viewer registry and
  ASP.NET Core TestServer authorization using **test-only claims**. Verifies
  reserved/unknown subject denial, active viewer access, role exclusivity,
  and immediate database-first revocation. It does **not** create or activate
  a real Keycloak viewer account.
- `master_reservation_concurrency.py`: concurrent singleton reservation
  and database durability checks.
- `provisioning_lock_test.py`: PostgreSQL advisory lease behavior.

The viewer authorization test is not a replacement for a future
Keycloak-issued viewer JWT E2E test. That test belongs with the guarded viewer
provisioning and credential enrollment implementation. All test identities
and passwords are isolated CI fixtures; never reuse them in production.
