# Active master authorization — M2 foundation

`ActiveMasterAuthorization.IsActiveMasterSubjectAsync(validatedTokenSubject, hasValidatedMasterRole)` requires BOTH a trusted, validated master role and an exact ordinal match between the token subject and the active PostgreSQL master subject. Pending, missing, mismatched or blank subjects deny. Database errors propagate and must result in denial at the API boundary.

**Critical integration rule:** `hasValidatedMasterRole` is trusted only after the ASP.NET Core JWT bearer authentication middleware verifies signature, issuer, audience, expiration and intended role semantics. Do not derive this boolean from unverified JWT payloads. The token's `sub` must be scoped to the correct realm/issuer. Do not cache positive master decisions across deactivation or identity changes.

**Not yet wired:** ASP.NET Core authorization policy/handler, JWT configuration, endpoints and integration tests. This commit provides the read-only persistence query and explicit runtime decision service, not a complete authorization system.

## ASP.NET Core policy integration (next increment)

Register a scoped `MasterReservationStore` backed by the deployment's `NpgsqlDataSource`, and call `services.AddOryvaActiveMasterPolicy()`. Require the `Oryva.ActiveMaster` policy on master-only endpoints. Authentication must be configured separately with JWT bearer validation of signature, exact Keycloak realm issuer, API audience, lifetime, and accepted algorithms. A trusted token-validation step must map **only** the direct Keycloak realm role `master` into the `oryva_realm_role=master` claim. Do not use a raw client-supplied role claim, nested unverified JSON, or a client role. Map the validated subject consistently to `sub` or `ClaimTypes.NameIdentifier`. Reject ambiguous/missing subjects.

The authorization handler checks PostgreSQL on every request; it does not cache grants. Database outages fail closed by propagating an exception, so the API boundary should return an unavailable/error response, never authorize on role alone.

**Not yet implemented:** Keycloak JWT bearer configuration, validated realm-role claim transformation, real protected API endpoints, and HTTP authorization integration tests. Do not expose master endpoints before those pieces are complete.
