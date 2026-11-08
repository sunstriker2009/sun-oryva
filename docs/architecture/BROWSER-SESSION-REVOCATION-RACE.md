# Browser-session revocation contention regression

**Status:** proposed CI regression; not a production enrollment endpoint.

The existing guarded PostgreSQL/TestServer suite now asserts that sixteen simultaneous same-origin, CSRF-validated HTTP requests attempting to revoke the same live browser bearer have **exactly one** successful database revocation. Only that winner may return the two cookie-deletion headers; every losing request must receive a generic 403 without Set-Cookie. The persisted bearer must be unusable afterward.

A separate negative assertion sends the original pre-rotation bearer to the revocation handler after a successful rotation. It must return 403 without Set-Cookie and must not invalidate the replacement bearer.

These tests preserve the original viewer state and do not enable accounts, alter Keycloak credentials, register public routes, or deliver email. They run in the existing full-stack workflow, not a new paid CI workflow.

## Verification and remaining work

The source change is **not yet verified by a successful run on its final PR head**. Verify the PostgreSQL/TestServer job and every required check before merge. Also outstanding: ambiguous network failure after a committed rotation, independent Keycloak email ownership verification, disabled-account credential enrollment, password recovery, SMTP/proxy production hardening and complete release security E2E. Cookie possession is never an authorization grant.
