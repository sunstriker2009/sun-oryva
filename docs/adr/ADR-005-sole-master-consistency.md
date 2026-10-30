# ADR-005 — Single-master invariant across PostgreSQL and Keycloak

**Status:** Accepted design; implementation pending.

Use ORYVA-owned PostgreSQL singleton state to serialize bootstrap and represent the unique application master. Use Keycloak for credential lifecycle and identity records. Because there is no cross-system distributed transaction, use durable pending state, stable identity correlation and idempotent reconciliation. The database constraint prevents multiple ORYVA master reservations, but **cannot alone prevent** privileged operators from manually assigning Keycloak master roles; administrative permissions and drift detection are required.

Alternatives rejected: startup-only in-memory checks; using a Keycloak role assignment count as the sole lock; embedding a predefined master password in an image or repository; treating Keycloak's infrastructure bootstrap administrator as the application master.

Production rollout blocked on implementation and concurrency/security integration tests.
