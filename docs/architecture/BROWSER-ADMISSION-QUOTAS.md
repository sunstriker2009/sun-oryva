# ORYVA browser admission quotas (migration 022)

**Status:** opt-in, unregistered backend foundation. Not a public enrollment route, not email ownership verification, not a browser session, and not credential authorization.

## Security contract

`OryvaBrowserAdmissionQuota` charges two PostgreSQL counters in a single transaction: a deployment-global counter and a source-IP counter. All replicas share the database clock's calendar-minute window and serialize updates using row locks (global first, IP second). Denied attempts also charge both counters. A saturated counter is bounded at the configured limit plus one, preventing unbounded counter growth. Limits are explicitly configured from 1 to 1000 per minute. The default API does **not** register the service or middleware.

IPv4-mapped IPv6 addresses normalize to IPv4; native IPv6 addresses are aggregated by /64 to reduce interface-ID rotation bypass. The database persists only a 64-character keyed HMAC-SHA256 partition digest and a single `global` row. No raw IP, invitation bearer, email, JWT subject or Keycloak identity is persisted. The HMAC key is a separate **deployment secret** of at least 32 random bytes, identical across all replicas; do not place it in Git, application logs or committed config. Rotation changes partitions and must be coordinated as a controlled deployment. Database administrators with the HMAC key may still correlate or brute-force low-entropy addresses, so treat the table as sensitive metadata.

`UseOryvaBrowserAdmissionQuota` checks only endpoints explicitly marked `OryvaBrowserCeremonyAttribute`, after routing. It reads `HttpContext.Connection.RemoteIpAddress` only, **never** `X-Forwarded-For`, `Forwarded` or similar untrusted request headers. A missing client IP, unavailable PostgreSQL or quota error fails closed with generic HTTP 503. Exceeding either limit returns generic HTTP 429 with conservative `Retry-After: 60`. Both responses suppress caching and referrer leakage; no address or token is returned.

## Deployment gates

1. Apply migration 022 after 021 and provision least-privilege table access for the runtime service.
2. Configure a non-default, securely stored random HMAC key identically on all replicas; do not use the CI test fixture key.
3. If deployed behind a proxy, configure ASP.NET Core Forwarded Headers middleware **only** with explicitly known proxy IPs/networks, restricted forwarded header count, and the correct middleware order. Strip client-supplied forwarding headers at the edge. An untrusted proxy chain or unknown client address must never be treated as verified. Without this configuration, the proxy's IP may be the quota partition, conservatively denying legitimate traffic. Review the ingress trust boundary before enabling any route.
4. Register the service and middleware explicitly, after routing and trusted-proxy processing, before any marked ceremony handler. Preserve the existing HTTPS/Host/Origin/CSRF guard and independent per-viewer exchange quota. Select limits and alert thresholds from measured traffic; monitor 429/503 counts without logging IPs or secrets.
5. Purge only old IP rows using an approved, rate-limited operation such as `DELETE FROM oryva.browser_admission_quotas WHERE scope='ip' AND updated_at < clock_timestamp() - interval '7 days'`. Preserve the global row. Define privacy retention and incident response before release.

The global counter deliberately serializes admission, so choose a conservative throughput envelope; this is a defense-in-depth browser gate, not a replacement for edge DDoS protection. The IP quota can deny legitimate users behind shared NAT. Per-viewer quotas remain independent and can be exhausted by an attacker knowing a viewer ID. No distributed throttle alone proves email ownership or permits enabling a disabled Keycloak identity.

## Validation and limitations

The isolated PostgreSQL + ASP.NET TestServer E2E covers 48 concurrent same-IP requests, 48 distinct-IP requests, saturated counters, IPv4-mapped and IPv6 /64 normalization, database-clock rollover, opaque persisted keys, forwarding-header spoof resistance, marked/unmarked endpoint isolation, 429 and missing-address 503. The schema workflow applies migration 022 twice and rejects plaintext IP partitions, extra global partitions and out-of-range counters.

**Still outstanding:** secure session issuance/rotation/revocation, reviewed reverse-proxy production configuration, independent Keycloak email ownership verification, one-time credential enrollment, password changes/recovery, production SMTP integration, complete lifecycle auditing and final browser security E2E. The API remains unmodified; no route, SMTP dispatch or account activation is enabled.
