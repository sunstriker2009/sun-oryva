# Master reservation database integration tests

The CI workflow runs these tests against an isolated PostgreSQL 17 service.

Coverage:
- 36 concurrent attempts across 12 threads converge on one durable pending reservation.
- A pending reservation remains after database connections close and reopen.
- The schema prevents a second singleton row.

These tests validate the **PostgreSQL reservation primitive only**. They do not simulate process crashes, Keycloak role assignment, identity reconciliation or multi-service end-to-end bootstrap. The .NET store itself requires a separate integration test suite.
