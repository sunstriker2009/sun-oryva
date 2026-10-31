using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Sun.Security.Bootstrap;

namespace Sun.Security.AspNetCore;

/// <summary>Runs on each authorization request; never caches positive decisions.</summary>
public sealed class ActiveMasterHandler(ActiveMasterAuthorization authorization)
    : AuthorizationHandler<ActiveMasterRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, ActiveMasterRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true)
            return;

        // Claim mapping must be configured only for the validated Keycloak realm.
        // Do not accept unverified role assertions or client-level roles.
        var subject = context.User.FindFirstValue(ClaimTypes.NameIdentifier)
            ?? context.User.FindFirstValue("sub");
        var isMaster = context.User.HasClaim("oryva_realm_role", "master");
        if (await authorization.IsActiveMasterSubjectAsync(subject, isMaster))
            context.Succeed(requirement);
        // Store exceptions propagate; authorization must never fall back to role-only.
    }
}
