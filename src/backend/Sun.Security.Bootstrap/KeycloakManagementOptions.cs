namespace Sun.Security.Bootstrap;

/// <summary>Configuration for a dedicated, least-privileged Keycloak service client.</summary>
public sealed class KeycloakManagementOptions
{
    public required Uri BaseAddress { get; init; }
    public string Realm { get; init; } = "oryva";
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }

    public void Validate()
    {
        if (BaseAddress.Scheme != Uri.UriSchemeHttps && !BaseAddress.IsLoopback)
            throw new InvalidOperationException("Keycloak management requires HTTPS except on loopback.");
        if (!BaseAddress.IsAbsoluteUri)
            throw new InvalidOperationException("Keycloak base address must be absolute.");
        if (string.IsNullOrWhiteSpace(Realm) || Realm.Contains('/'))
            throw new InvalidOperationException("Invalid Keycloak realm.");
        if (string.IsNullOrWhiteSpace(ClientId) || string.IsNullOrWhiteSpace(ClientSecret))
            throw new InvalidOperationException("Dedicated Keycloak client credentials are required.");
    }
}
