using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Sun.Security.Bootstrap;

namespace Sun.Security.AspNetCore;

public static class ActiveMasterPolicyExtensions
{
    public const string PolicyName = "Oryva.ActiveMaster";

    /// <summary>Requires an already configured JWT bearer authentication scheme.
    /// The JWT validation pipeline must map the trusted realm role to
    /// oryva_realm_role; this extension never trusts raw token payloads.</summary>
    public static IServiceCollection AddOryvaActiveMasterPolicy(this IServiceCollection services)
    {
        services.AddScoped<ActiveMasterAuthorization>();
        services.AddScoped<IAuthorizationHandler, ActiveMasterHandler>();
        services.AddAuthorizationBuilder()
            .AddPolicy(PolicyName, policy => policy
                .RequireAuthenticatedUser()
                .AddRequirements(new ActiveMasterRequirement()));
        return services;
    }
}
