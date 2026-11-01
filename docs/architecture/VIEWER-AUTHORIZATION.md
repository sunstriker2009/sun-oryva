# Viewer authorization — database-first foundation

ORYVA's `Oryva.Viewer` policy now requires an **exclusive validated Keycloak
realm role** and an active PostgreSQL subject. A `viewer` JWT alone never
authorizes a request. The `admin` realm role continues to grant read-only
viewer access **only** while the same subject is an active admin in PostgreSQL.
The `master` role does not implicitly inherit viewer permissions.

## Deployment and runtime

Apply `infrastructure/postgres/007_viewer_authorization.sql` after 006,
before deploying this API version. The new `oryva.viewer_accounts` table
contains a unique Keycloak subject binding, case-insensitive unique email,
original requesting actor/role, and a constrained state. Only `state='active'`
can satisfy the viewer policy; missing or deactivated subjects are denied.
Authorization queries run on every request without a positive cache. Database
errors are not converted into authorization success.

`GET /api/viewer/session` is a read-only policy demonstration. The viewer
policy is reusable by consumers via `AddOryvaRolePolicies()`. JWT signature,
issuer, audience, lifetime, and realm-role mapping are validated by the
existing OIDC bearer middleware, not by the PostgreSQL store.

## Security boundaries and remaining work

This increment **does not** expose any viewer account creation, activation,
credential enrollment, role assignment, or deactivation endpoint. SQL writes
in the isolated HTTP E2E runner are **test fixtures only**, not a production
provisioning path. Before exposing viewer mutations, add master/admin
authorization, Keycloak ownership-marker validation, disabled-account
provisioning, role exclusivity, secure enrollment, durable state transitions,
database-first revocation, session logout, audit events and recovery from
ambiguous Keycloak responses. Do not activate an account merely because it
has a Keycloak viewer role.

The PostgreSQL/ASP.NET Core E2E verifies reserved/missing subject denial,
exclusive role claims, subject binding, active authorization, and immediate
denial following a database state change. A separate Keycloak-issued viewer
JWT end-to-end scenario remains to be added when the guarded viewer
provisioning workflow exists.
