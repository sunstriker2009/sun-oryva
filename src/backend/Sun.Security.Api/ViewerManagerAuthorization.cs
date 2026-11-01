using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Sun.Security.AspNetCore;

namespace Sun.Security.Api;

/// <summary>
/// Viewer management is permitted to an active master or active admin only.
/// Both branches recheck PostgreSQL; a role-only JWT never authorizes writes.
/// </summary>
public static class ViewerManagerAuthorization
{
    public static async Task<string?> GetActorRoleAsync(
        IAuthorizationService authorization, ClaimsPrincipal principal)
    {
        var master = await authorization.AuthorizeAsync(
            principal, ActiveMasterPolicyExtensions.PolicyName);
        if (master.Succeeded) return "master";
        var admin = await authorization.AuthorizeAsync(
            principal, OryvaRolePolicyExtensions.Admin);
        return admin.Succeeded ? "admin" : null;
    }
}
