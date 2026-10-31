namespace Sun.Security.AspNetCore;

public sealed class OryvaJwtOptions
{
    /// <summary>Exact Keycloak realm issuer, e.g. https://identity.example/realms/oryva.</summary>
    public required string Issuer { get; init; }
    /// <summary>API audience expected in the access token's aud claim.</summary>
    public required string Audience { get; init; }
}
