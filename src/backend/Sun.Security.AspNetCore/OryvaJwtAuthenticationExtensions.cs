using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Sun.Security.AspNetCore;

/// <summary>Configures bearer authentication against a single trusted Keycloak realm.</summary>
public static class OryvaJwtAuthenticationExtensions
{
    public static IServiceCollection AddOryvaKeycloakJwt(
        this IServiceCollection services, OryvaJwtOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!Uri.TryCreate(options.Issuer, UriKind.Absolute, out var issuer) ||
            issuer.Scheme != Uri.UriSchemeHttps ||
            !issuer.AbsolutePath.TrimEnd('/').EndsWith("/realms/oryva", StringComparison.Ordinal) ||
            !string.IsNullOrWhiteSpace(issuer.Query) ||
            !string.IsNullOrWhiteSpace(issuer.Fragment) ||
            string.IsNullOrWhiteSpace(options.Audience))
            throw new ArgumentException("Require an HTTPS ORYVA realm issuer and nonempty API audience.");

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(bearer =>
            {
                bearer.MapInboundClaims = false;
                bearer.Authority = options.Issuer.TrimEnd('/');
                bearer.RequireHttpsMetadata = true;
                bearer.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = options.Issuer.TrimEnd('/'),
                    ValidateAudience = true,
                    ValidAudience = options.Audience,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidateIssuerSigningKey = true,
                    NameClaimType = "sub",
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256]
                };
                bearer.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        if (context.Principal?.Identity is not ClaimsIdentity identity)
                        {
                            context.Fail("Missing authenticated identity.");
                            return Task.CompletedTask;
                        }

                        var subject = identity.FindFirst("sub")?.Value;
                        if (string.IsNullOrWhiteSpace(subject) ||
                            identity.FindAll("sub").Count() != 1)
                        {
                            context.Fail("Missing or ambiguous token subject.");
                            return Task.CompletedTask;
                        }

                        // Only derive the internal role from the validated realm_access
                        // JSON claim; never accept an incoming or client role as trusted.
                        if (identity.HasClaim(claim => claim.Type == "oryva_realm_role"))
                        {
                            context.Fail("Untrusted internal role claim present in access token.");
                            return Task.CompletedTask;
                        }
                        var realmClaims = identity.FindAll("realm_access").ToArray();
                        if (realmClaims.Length != 1)
                            return Task.CompletedTask;
                        try
                        {
                            using var document = JsonDocument.Parse(realmClaims[0].Value);
                            if (document.RootElement.ValueKind == JsonValueKind.Object &&
                                document.RootElement.TryGetProperty("roles", out var roles) &&
                                roles.ValueKind == JsonValueKind.Array &&
                                roles.EnumerateArray().Any(role =>
                                    role.ValueKind == JsonValueKind.String &&
                                    role.GetString() == "master"))
                                identity.AddClaim(new Claim("oryva_realm_role", "master"));
                        }
                        catch (JsonException)
                        {
                            context.Fail("Malformed realm role claim.");
                        }
                        return Task.CompletedTask;
                    }
                };
            });
        return services;
    }
}
