using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Restricted Keycloak management API adapter. No credentials or tokens are logged.
/// Caller owns authorization, reconciliation and sole-master policy enforcement.
/// </summary>
public sealed class KeycloakManagementClient(HttpClient http, KeycloakManagementOptions options)
{
    public async Task<KeycloakUser?> FindUserByUsernameAsync(
        string username, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        options.Validate();
        var token = await GetTokenAsync(cancellationToken);
        var path = $"admin/realms/{Uri.EscapeDataString(options.Realm)}/users?username={Uri.EscapeDataString(username)}&exact=true&max=2";
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(options.BaseAddress, path));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await http.SendAsync(request, cancellationToken);
        KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
        var users = await response.Content.ReadFromJsonAsync<List<KeycloakUser>>(cancellationToken);
        if (users is null || users.Count == 0) return null;
        if (users.Count != 1 || !string.Equals(users[0].Username, username, StringComparison.Ordinal))
            throw new InvalidOperationException("Ambiguous Keycloak user lookup.");
        return users[0];
    }

    /// <summary>Creates a disabled identity. Does not assign roles, credentials or enable it.</summary>
    public async Task CreateDisabledUserAsync(
        string username, string email, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        options.Validate();
        var token = await GetTokenAsync(cancellationToken);
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(options.BaseAddress, $"admin/realms/{Uri.EscapeDataString(options.Realm)}/users"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content = JsonContent.Create(new
        {
            username,
            email,
            enabled = false,
            emailVerified = false
        });
        using var response = await http.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
            throw new InvalidOperationException("Keycloak user already exists; reconcile before proceeding.");
        KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>Creates a disabled user with deployment ownership metadata.</summary>
    public async Task CreateDisabledOwnedUserAsync(
        string username, string email, string ownershipMarker,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(ownershipMarker);
        options.Validate();
        var token = await GetTokenAsync(cancellationToken);
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(options.BaseAddress, $"admin/realms/{Uri.EscapeDataString(options.Realm)}/users"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content = JsonContent.Create(new
        {
            username,
            email,
            enabled = false,
            emailVerified = false,
            attributes = new Dictionary<string, string[]>
            {
                [MasterIdentityOwnership.AttributeName] = [ownershipMarker]
            }
        });
        using var response = await http.SendAsync(request, cancellationToken);
        if (response.StatusCode == HttpStatusCode.Conflict)
            throw new InvalidOperationException("Keycloak username already exists; reconcile before proceeding.");
        KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Sets an initial password for a disabled bootstrap identity.
    /// Caller must hold the provisioning lease and verify ownership.
    /// Never log or persist the password.
    /// </summary>
    public async Task SetInitialPasswordAsync(
        string subjectId, string password, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(password);
        if (password.Length < 16)
            throw new ArgumentException("Initial master password must be at least 16 characters.", nameof(password));

        options.Validate();
        var token = await GetTokenAsync(cancellationToken);
        using var request = new HttpRequestMessage(
            HttpMethod.Put,
            new Uri(options.BaseAddress,
                $"admin/realms/{Uri.EscapeDataString(options.Realm)}/users/{Uri.EscapeDataString(subjectId)}/reset-password"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content = JsonContent.Create(new { type = "password", value = password, temporary = false });
        using var response = await http.SendAsync(request, cancellationToken);
        KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Low-level identity enablement transport. Call only from the guarded coordinator.
    /// A lost response must be reconciled by rereading Keycloak before retrying.
    /// </summary>
    public async Task EnableUserAsync(
        string subjectId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        options.Validate();
        var token = await GetTokenAsync(cancellationToken);
        using var request = new HttpRequestMessage(
            HttpMethod.Put,
            new Uri(options.BaseAddress,
                $"admin/realms/{Uri.EscapeDataString(options.Realm)}/users/{Uri.EscapeDataString(subjectId)}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content = JsonContent.Create(new { enabled = true });
        using var response = await http.SendAsync(request, cancellationToken);
        KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
    }

    /// <summary>
    /// Low-level realm role mapping transport. This method does not enforce the
    /// sole-master policy; callers must use the guarded coordinator.
    /// </summary>
    public async Task AddMasterRoleMappingAsync(
        string subjectId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        options.Validate();
        var realm = Uri.EscapeDataString(options.Realm);
        var token = await GetTokenAsync(cancellationToken);

        using var lookup = new HttpRequestMessage(
            HttpMethod.Get, new Uri(options.BaseAddress, $"admin/realms/{realm}/roles/master"));
        lookup.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var roleResponse = await http.SendAsync(lookup, cancellationToken);
        KeycloakHttpClientFactory.EnsureNoRedirect(roleResponse);
        roleResponse.EnsureSuccessStatusCode();
        var role = await roleResponse.Content.ReadFromJsonAsync<KeycloakRealmRole>(cancellationToken)
            ?? throw new InvalidOperationException("Master role lookup returned no representation.");
        if (string.IsNullOrWhiteSpace(role.Id) ||
            !string.Equals(role.Name, "master", StringComparison.Ordinal))
            throw new InvalidOperationException("Invalid Keycloak master role representation.");

        using var assign = new HttpRequestMessage(
            HttpMethod.Post,
            new Uri(options.BaseAddress,
                $"admin/realms/{realm}/users/{Uri.EscapeDataString(subjectId)}/role-mappings/realm"));
        assign.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        assign.Content = JsonContent.Create(new[] { role });
        using var response = await http.SendAsync(assign, cancellationToken);
        KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
    }

    private sealed record KeycloakRealmRole(
        [property: JsonPropertyName("id")] string Id,
        [property: JsonPropertyName("name")] string Name);

    /// <summary>Returns all direct members of the realm-level master role; paginated and fail-closed.</summary>
    public async Task<IReadOnlyList<KeycloakUser>> GetMasterRoleMembersAsync(
        CancellationToken cancellationToken = default)
    {
        options.Validate();
        var token = await GetTokenAsync(cancellationToken);
        var members = new List<KeycloakUser>();
        const int pageSize = 100;
        for (var first = 0; ; first += pageSize)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                new Uri(options.BaseAddress,
                    $"admin/realms/{Uri.EscapeDataString(options.Realm)}/roles/master/users?first={first}&max={pageSize}"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var response = await http.SendAsync(request, cancellationToken);
            KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
            var page = await response.Content.ReadFromJsonAsync<List<KeycloakUser>>(cancellationToken)
                ?? throw new InvalidOperationException("Invalid Keycloak role membership response.");
            members.AddRange(page);
            if (members.Count > 1)
                return members; // More than one master is always invalid; avoid further requests.
            if (page.Count < pageSize)
                return members;
        }
    }

    private async Task<string> GetTokenAsync(CancellationToken cancellationToken)
    {
        using var body = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = options.ClientId,
            ["client_secret"] = options.ClientSecret
        });
        using var tokenRequest = new HttpRequestMessage(HttpMethod.Post,
            new Uri(options.BaseAddress, $"realms/{Uri.EscapeDataString(options.Realm)}/protocol/openid-connect/token"))
        {
            Content = body
        };
        using var response = await http.SendAsync(tokenRequest, cancellationToken);
        KeycloakHttpClientFactory.EnsureNoRedirect(response);
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<KeycloakToken>(cancellationToken)
            ?? throw new InvalidOperationException("Empty Keycloak token response.");
        if (string.IsNullOrWhiteSpace(payload.AccessToken))
            throw new InvalidOperationException("Missing Keycloak access token.");
        return payload.AccessToken;
    }

    private sealed record KeycloakToken([property: JsonPropertyName("access_token")] string AccessToken);
}

public sealed record KeycloakUser(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("enabled")] bool Enabled,
    [property: JsonPropertyName("attributes")] Dictionary<string, List<string>>? Attributes = null);
