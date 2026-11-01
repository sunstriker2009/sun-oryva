using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Authorization for ordinary realm roles. Master-only operations must always
/// use Oryva.ActiveMaster, which additionally checks PostgreSQL ownership.
/// </summary>
public static class OryvaRolePolicyExtensions
{
    public const string Admin = "Oryva.Admin";
    public const string Viewer = "Oryva.Viewer";

    public static IServiceCollection AddOryvaRolePolicies(this IServiceCollection services)
    {
        services.AddAuthorizationBuilder()
            .AddPolicy(Admin, policy => policy.RequireAuthenticatedUser()
                .RequireClaim("oryva_realm_role", "admin"))
            .AddPolicy(Viewer, policy => policy.RequireAuthenticatedUser()
                .RequireClaim("oryva_realm_role", "viewer", "admin"));
        return services;
    }
}
