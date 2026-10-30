# ADR-003: Initial roles and authorization

**Status: Proposed — implementation design pending**

Start with master, admin and viewer profiles backed by explicit permissions and server-side policies. Only the master may create/manage admins. Admins may manage viewers but cannot elevate privileges. Exactly one master per isolated deployment. Host-specific operations remain in the host with explicitly delegated permissions. Define concurrency, authoritative role store and revocation behavior before acceptance.
