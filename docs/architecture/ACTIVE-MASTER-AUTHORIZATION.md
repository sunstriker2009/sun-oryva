# Active master authorization — M2 foundation

`ActiveMasterAuthorization.IsActiveMasterSubjectAsync(validatedTokenSubject, hasValidatedMasterRole)` requires BOTH a trusted, validated master role and an exact ordinal match between the token subject and the active PostgreSQL master subject. Pending, missing, mismatched or blank subjects deny. Database errors propagate and must result in denial at the API boundary.

**Critical integration rule:** `hasValidatedMasterRole` is trusted only after the ASP.NET Core JWT bearer authentication middleware verifies signature, issuer, audience, expiration and intended role semantics. Do not derive this boolean from unverified JWT payloads. The token's `sub` must be scoped to the correct realm/issuer. Do not cache positive master decisions across deactivation or identity changes.

**Not yet wired:** ASP.NET Core authorization policy/handler, JWT configuration, endpoints and integration tests. This commit provides the read-only persistence query and explicit runtime decision service, not a complete authorization system.
