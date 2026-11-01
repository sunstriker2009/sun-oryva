using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Sun.Security.Bootstrap;

namespace Sun.Security.AspNetCore;

/// <summary>Requires an exclusive validated realm role and, for admin,
/// a committed active PostgreSQL subject. Viewer tokens are read-only.</summary>
public sealed class OryvaRoleRequirement(bool allowViewer) : IAuthorizationRequirement
{
    public bool AllowViewer { get; } = allowViewer;
}

/// <summary>
/// No positive authorization caching: an admin's database state is checked
/// for every request, including viewer endpoints accessed by admins.
/// </summary>
public sealed class OryvaRoleAuthorizationHandler(ActiveAdminAuthorization admins)
    : AuthorizationHandler<OryvaRoleRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, OryvaRoleRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true) return;
        var roles = context.User.FindAll("oryva_realm_role").Select(x => x.Value).ToArray();
        // Fail closed on duplicate or conflicting claims, even for test identities.
        if (roles.Length != 1) return;
        if (requirement.AllowViewer && roles[0] == "viewer")
        {
            context.Succeed(requirement);
            return;
        }
        if (roles[0] != "admin") return;
        var subjects = context.User.FindAll("sub").Select(x => x.Value).ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0])) return;
        if (await admins.IsActiveAdminSubjectAsync(subjects[0], true))
            context.Succeed(requirement);
        // PostgreSQL errors propagate: never fall back to role-only access.
    }
}
