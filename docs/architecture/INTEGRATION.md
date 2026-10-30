# Integration Contracts — planned

Consumers integrate via `Sun.Security.AspNetCore` and `@sun-security/nextjs` / `@sun-security/react`, with minimal configuration for issuer, audience, client identity, and policy mapping. Prefer OIDC discovery and standard token validation. No consumer may need ORYVA management API access for ordinary authenticated requests. Privileged administration uses explicit management endpoints and server-side credentials only.

Package boundaries are proposals: `Sun.Security.Abstractions`, `Sun.Security.Authentication`, `Sun.Security.Authorization`, `Sun.Security.Identity`, `Sun.Security.Auditing`, `Sun.Security.AspNetCore`, `Sun.Security.Management.Api`; `@sun-security/core`, `@sun-security/react`, `@sun-security/nextjs`, `@sun-security/ui`, `@sun-security/tokens`. Independent SemVer and compatibility matrix are planned. No packages have been released.
