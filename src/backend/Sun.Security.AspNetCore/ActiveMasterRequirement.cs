using Microsoft.AspNetCore.Authorization;

namespace Sun.Security.AspNetCore;

/// <summary>Requires an authenticated principal with a validated master role
/// and an active PostgreSQL subject binding.</summary>
public sealed class ActiveMasterRequirement : IAuthorizationRequirement;
