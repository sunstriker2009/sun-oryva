# ORYVA invitation outbox health — internal monitoring contract

**Status:** Internal read-only PostgreSQL aggregate snapshot. This does not
register a hosted worker, open a management or public endpoint, enable SMTP,
verify email ownership, set a password, or activate an account.

`ViewerInvitationOutboxHealthStore.ReadAsync` samples the existing outbox
with one SQL statement using PostgreSQL server time. The result contains only
the timestamp and low-cardinality aggregate counters:

| Counter | Meaning |
|---|---|
| Pending | Queued or retry-waiting deliveries |
| DuePending | Pending records whose retry time has arrived, not necessarily eligible |
| Leased | Records claimed by a worker |
| ExpiredLeases | Leases past their fencing expiry, awaiting reclaim or sweep |
| RetryPending | Pending records with at least one previous claim |
| ExhaustedUnsent | Pending or leased records at the five-attempt limit |
| RelayAccepted | SMTP DATA accepted by a relay; **not** recipient inbox delivery |
| Cancelled | Terminal cancellations, including expiry and revocation |

The snapshot deliberately does not join recipients, identities, challenge IDs,
encryption envelopes or audit event details. It must remain internal; any
future operator endpoint needs separate authentication, role authorization,
rate limiting and threat review. Do not add per-recipient labels, challenge
identifiers or high-cardinality dimensions to exported telemetry.

## Suggested operator checks

Monitor sustained growth in `DuePending`, `ExpiredLeases`,
`ExhaustedUnsent`, and unexpected changes in `RelayAccepted` relative to
invitation issuance. Define thresholds using real staging traffic and
operational objectives rather than inventing fixed production limits. A
zero-count snapshot does not prove the mail relay is reachable, and a failed
database read must surface as a monitoring failure rather than silently
reporting zero. Never treat counters as authorization to dispatch.

The isolated PostgreSQL/Mailpit integration test covers queued, delayed retry,
expired lease, exhausted attempt and cancelled transitions and verifies that
the serialized snapshot contains no per-invitation information. It does not
test a production relay, deliverability, account enrollment or activation.

**Release gates still open:** approved staging relay, secret rotation and
restricted egress; browser email proof and credential enrollment in a disabled
Keycloak account; abuse limits; least-privilege grants; operational incident
response and final security review. The sole-master, master-only admin
creation, master/admin viewer management and read-only viewer invariants are
unchanged.
