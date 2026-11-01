using Microsoft.AspNetCore.Authorization;
using Sun.Security.Bootstrap;

namespace Sun.Security.AspNetCore;

/// <summary>Requires an exclusive validated realm role and a committed active
/// PostgreSQL subject. Admin may access viewer routes; viewer cannot access admin.</summary>
public sealed class OryvaRoleRequirement(bool allowViewer) : IAuthorizationRequirement
{
    public bool AllowViewer { get; } = allowViewer;
}

/// <summary>
/// No positive authorization caching: admin and viewer states are checked
/// on every request. A revoked subject is denied even with a valid old JWT.
/// </summary>
public sealed class OryvaRoleAuthorizationHandler(
    ActiveAdminAuthorization admins, ActiveViewerAuthorization viewers)
    : AuthorizationHandler<OryvaRoleRequirement>
{
    protected override async Task HandleRequirementAsync(
        AuthorizationHandlerContext context, OryvaRoleRequirement requirement)
    {
        if (context.User.Identity?.IsAuthenticated != true) return;
        var roles = context.User.FindAll("oryva_realm_role").Select(x => x.Value).ToArray();
        // Fail closed on missing, duplicate or conflicting realm-role claims.
        if (roles.Length != 1) return;
        var subjects = context.User.FindAll("sub").Select(x => x.Value).ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0])) return;

        if (roles[0] == "viewer" && requirement.AllowViewer)
        {
            if (await viewers.IsActiveViewerSubjectAsync(subjects[0], true))
                context.Succeed(requirement);
            return;
        }
        if (roles[0] != "admin") return;
        if (await admins.IsActiveAdminSubjectAsync(subjects[0], true))
            context.Succeed(requirement);
        // Database errors propagate; never fall back to role-only access.
    }
}
