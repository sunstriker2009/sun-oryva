# Management write throttling (backend v1)

Privileged management POST endpoints use two independent defenses: a
process-local fixed-window limiter and a **PostgreSQL-backed cross-replica
fixed-minute quota**. The latter is implemented by
`OryvaDistributedManagementWriteQuota` and must be migrated with
`infrastructure/postgres/013_management_write_quotas.sql` **before**
starting updated API replicas. An unavailable quota database rejects writes,
rather than falling back to a process-local limit.

Both limiters use `ORYVA_MANAGEMENT_WRITE_LIMIT_PER_MINUTE` (default 10;
allowed 1–120). Startup rejects invalid settings. All 10 privileged
management POST routes are marked with `Oryva.ManagementWrite`; future
mutation routes must opt in explicitly and be reviewed for coverage.

## Enforcement and HTTP contract

The API runs routing, authentication and authorization, then the local
limiter and PostgreSQL quota middleware, before executing account handlers.
The partition is the single authenticated `sub` claim, **not**
`X-Forwarded-For` or other caller-controlled headers. A SHA-256 digest of
the partition key is stored, never the raw JWT subject or a bearer token.
All replicas sharing one PostgreSQL database share the same quota.

The SQL operation is one atomic `INSERT ... ON CONFLICT DO UPDATE ...
WHERE ... RETURNING`, with the PostgreSQL server clock determining the
calendar-minute bucket. Concurrent writes for one subject serialize at the
row; at most the configured number can be admitted per bucket across
replicas. The database does not reset a newer bucket to an older one if
the server clock moves backward.

When exhausted, the API responds **429** with
`{"error":"management_rate_limit_exceeded"}`, `Cache-Control: no-store`
and a conservative `Retry-After: 60` for the distributed limiter.
A database outage, missing migration or SQL failure returns **503** with
`{"error":"management_quota_unavailable"}` and `Cache-Control: no-store`.
Rejected writes never invoke the management handler or Keycloak.

## Deployment and operations

- Apply migration 013 after migration 012, before rolling out API instances.
  Do not deploy new replicas before the table and application role grants
  have been verified. The table is created with PUBLIC privileges revoked;
  explicitly grant the application role only SELECT, INSERT and UPDATE
  (not DELETE, TRUNCATE, DDL or schema ownership).
- Quotas are fixed calendar-minute windows, not a rolling-window or
  token-bucket guarantee. Requests straddling a minute boundary can burst.
  Configure trusted edge protection and separate per-target quotas for
  login, password recovery, invitations and email sending before production.
- Counter rows are retained until pruned. An operator-controlled maintenance
  job can delete rows where `updated_at < now() - interval '2 days'`;
  grant DELETE only to that separate maintenance role. Never delete active
  counters. Monitor table growth, database latency and 503 rates.
- This quota is **defense in depth**, not authorization. PostgreSQL-backed
  master/admin/viewer subject checks, Keycloak ownership, durable state
  transitions, audit and advisory locks remain mandatory.

## Verification

Real PostgreSQL E2E exercises concurrent quota consumption from independent
connection pools, subject isolation and the HTTP middleware's 429,
no-handler-execution, anonymous denial and read-only bypass. Schema CI
applies migration 013 twice and checks malformed keys and counter limits.
All relevant CI must pass before this milestone is marked delivered.
