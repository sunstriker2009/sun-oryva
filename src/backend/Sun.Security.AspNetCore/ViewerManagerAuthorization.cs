using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Viewer management is permitted to an active master or active admin only.
/// Both branches recheck PostgreSQL; a role-only JWT never authorizes writes.
/// </summary>
public static class ViewerManagerAuthorization
{
    public static async Task<string?> GetActorRoleAsync(
        IAuthorizationService authorization, ClaimsPrincipal principal)
    {
        // Reject ambiguous or composite role claims before either policy branch.
        var roles = principal.FindAll("oryva_realm_role").Select(x => x.Value).ToArray();
        var subjects = principal.FindAll("sub").Select(x => x.Value).ToArray();
        if (roles.Length != 1 || roles[0] is not ("master" or "admin") ||
            subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0]))
            return null;
        var master = await authorization.AuthorizeAsync(
            principal, ActiveMasterPolicyExtensions.PolicyName);
        if (master.Succeeded) return "master";
        var admin = await authorization.AuthorizeAsync(
            principal, OryvaRolePolicyExtensions.Admin);
        return admin.Succeeded ? "admin" : null;
    }
}
