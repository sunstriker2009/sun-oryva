# Management write throttling (backend v1 defense in depth)

All privileged account-management **POST** endpoints use the
`Oryva.ManagementWrite` ASP.NET Core fixed-window limiter. The default is
**10 requests per authenticated subject per minute**, with no queue. Set
`ORYVA_MANAGEMENT_WRITE_LIMIT_PER_MINUTE` to an integer from **1 to 120**
to override the limit. Invalid configuration fails startup.

## Request order and response

The API explicitly routes, authenticates and authorizes before invoking
the limiter. The quota key is the single validated `sub` claim, **never**
a caller-controlled `X-Forwarded-For` header. Missing/ambiguous subjects
share a fail-closed partition and remain subject to endpoint authorization.
All management POST routes share the same quota per subject, so rotating
paths cannot bypass the local limiter. Viewer, admin and master access
rules are unchanged; viewer read-only requests and health checks are not
management writes.

On exhaustion the API responds **429** with
`{"error":"management_rate_limit_exceeded"}`, `Cache-Control: no-store`
and `Retry-After` when the rate-limit lease provides a retry estimate.
There is no waiting queue. A rejected request never invokes its account
management handler or calls Keycloak.

## Security and operational limits

**This is a process-local limit, not a distributed abuse-prevention system.**
Each API replica has its own counters and counters reset on restart. A
multi-replica production deployment MUST use a trusted, centrally enforced
edge or distributed rate limiter as well, with quotas for authentication,
password reset, email delivery and invitation issuance. Do not trust
unconfigured proxy forwarding headers for partitioning. Apply separate
account and email-target quotas to future invitation/password flows.

An authorized actor can still exhaust their own quota; choose a limit
consistent with operational recovery workflows. The limiter is not an
authorization control and never replaces PostgreSQL-backed active-account
checks, Keycloak ownership verification, advisory locks, audit trails or
durable transitions.

## Verification

The PostgreSQL-backed viewer HTTP integration runner also creates an
isolated ASP.NET Core TestServer with this real limiter middleware. It
verifies unauthenticated rejection, shared quota across POST routes,
429 response contract, isolation of different subjects, unaffected reads,
untrusted forwarding headers, invalid configuration and ambiguous-subject
partitioning. Full-stack CI remains required before merging.
