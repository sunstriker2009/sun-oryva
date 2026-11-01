using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Sun.Security.Bootstrap;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Master operations require Oryva.ActiveMaster. Admin access requires
/// a validated admin role AND active PostgreSQL provisioning state.
/// Viewer access requires an active viewer subject or an active admin.
/// </summary>
public static class OryvaRolePolicyExtensions
{
    public const string Admin = "Oryva.Admin";
    public const string Viewer = "Oryva.Viewer";

    public static IServiceCollection AddOryvaRolePolicies(this IServiceCollection services)
    {
        services.AddScoped<ActiveAdminAuthorization>();
        services.AddScoped<ViewerAccountStore>();
        services.AddScoped<ActiveViewerAuthorization>();
        services.AddScoped<IAuthorizationHandler, OryvaRoleAuthorizationHandler>();
        services.AddAuthorizationBuilder()
            .AddPolicy(Admin, policy => policy.RequireAuthenticatedUser()
                .AddRequirements(new OryvaRoleRequirement(false)))
            .AddPolicy(Viewer, policy => policy.RequireAuthenticatedUser()
                .AddRequirements(new OryvaRoleRequirement(true)));
        return services;
    }
}
