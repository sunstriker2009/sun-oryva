using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Sun.Security.AspNetCore;
using Npgsql;
using Sun.Security.Bootstrap;

var dsn = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("Missing test database URL.");
var secret = Environment.GetEnvironmentVariable("ORYVA_TEST_CLIENT_SECRET")
    ?? throw new InvalidOperationException("Missing test client secret.");
const string username = "e2e-master";
const string deployment = "e2e-isolated-deployment";
const string password = "E2e-Strong-Password-Only-2026!";
await using var dataSource = NpgsqlDataSource.Create(dsn);
var store = new MasterReservationStore(dataSource);
var provisioningLock = new MasterProvisioningLock(dataSource);
using var http = KeycloakHttpClientFactory.Create();
var keycloak = new KeycloakManagementClient(http, new KeycloakManagementOptions
{
    BaseAddress = new Uri("http://127.0.0.1:8080/"),
    ClientId = "oryva-e2e-bootstrap",
    ClientSecret = secret
});
var coordinator = new MasterProvisioningCoordinator(provisioningLock, store, keycloak);
var verifier = new MasterIdentityVerifier(store, keycloak, provisioningLock);

static async Task RejectAsync(Func<Task> operation, string scenario)
{
    try { await operation(); }
    catch (InvalidOperationException) { Console.WriteLine("PASS rejected: " + scenario); return; }
    throw new Exception("Expected rejection: " + scenario);
}
if ((await store.ReserveAsync()).IsActive)
    throw new Exception("Fresh deployment already has active master.");
await using (var competingLease = await provisioningLock.TryAcquireAsync()
    ?? throw new Exception("Failed to acquire test provisioning lease."))
{
    await RejectAsync(
        () => coordinator.PrepareAsync(username, "master@example.invalid", deployment),
        "concurrent coordinator blocked by advisory lease");
}
var authorization = new ActiveMasterAuthorization(store);
if (await authorization.IsActiveMasterSubjectAsync("any-subject", true))
    throw new Exception("Pending reservation must not authorize master.");
if (await authorization.IsActiveMasterSubjectAsync("any-subject", false))
    throw new Exception("Missing master role must deny.");
Console.WriteLine("PASS M2 pending reservation and missing-role denial");
await coordinator.PrepareAsync(username, "master@example.invalid", deployment);
await coordinator.PrepareAsync(username, "master@example.invalid", deployment); // restart recovery
await RejectAsync(() => coordinator.EnablePreparedMasterAsync(username, deployment), "missing role/password");
await RejectAsync(() => coordinator.SetPreparedInitialPasswordAsync(username, "wrong-deployment", password), "ownership mismatch");
await coordinator.SetPreparedInitialPasswordAsync(username, deployment, password);
await coordinator.AssignPreparedMasterRoleAsync(username, deployment);
await coordinator.AssignPreparedMasterRoleAsync(username, deployment); // role retry
await RejectAsync(() => coordinator.EnablePreparedMasterAsync(username, "wrong-deployment"), "wrong enablement owner");
await coordinator.EnablePreparedMasterAsync(username, deployment);
await coordinator.EnablePreparedMasterAsync(username, deployment); // ambiguous response reconciliation
if ((await store.ReserveAsync()).IsActive)
    throw new Exception("Enabled Keycloak identity must not imply database activation.");
await RejectAsync(() => verifier.VerifyAndActivateAsync(username, "wrong-deployment"), "wrong activation owner");
var active = await verifier.VerifyAndActivateAsync(username, deployment);
if (!active.IsActive || string.IsNullOrWhiteSpace(active.SubjectId))
    throw new Exception("Activation failed.");
var repeated = await verifier.VerifyAndActivateAsync(username, deployment);
if (repeated.SubjectId != active.SubjectId ||
    (await store.ReserveAsync()).SubjectId != active.SubjectId)
    throw new Exception("Idempotent activation or runtime binding failed.");
if (!await authorization.IsActiveMasterSubjectAsync(active.SubjectId, true))
    throw new Exception("Active master subject with validated role must authorize.");
if (await authorization.IsActiveMasterSubjectAsync(active.SubjectId, false) ||
    await authorization.IsActiveMasterSubjectAsync("different-subject", true) ||
    await authorization.IsActiveMasterSubjectAsync(null, true) ||
    await authorization.IsActiveMasterSubjectAsync(" ", true))
    throw new Exception("M2 master authorization fail-closed check failed.");
Console.WriteLine("PASS M2 active subject binding and invalid subject/role denial");
await RejectAsync(() => coordinator.PrepareAsync("another-master", "other@example.invalid", deployment), "second master");
await RejectAsync(() => coordinator.SetPreparedInitialPasswordAsync(username, deployment, password), "password reset after activation");
await RejectAsync(() => coordinator.EnablePreparedMasterAsync(username, deployment), "enable after activation");

// Exercise the production authorization policy through ASP.NET Core's real
// authentication/authorization middleware, with a TEST-ONLY identity scheme.
// Keycloak token signature/issuer validation is outside this test's scope.
var webBuilder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder(
    new Microsoft.AspNetCore.Builder.WebApplicationOptions { EnvironmentName = "Development" });
webBuilder.WebHost.UseTestServer();
webBuilder.Services.AddSingleton(dataSource);
webBuilder.Services.AddScoped<MasterReservationStore>();
webBuilder.Services.AddScoped<AdminProvisioningStore>();
webBuilder.Services.AddAuthentication("E2E")
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions,
        E2EAuthenticationHandler>("E2E", _ => { });
webBuilder.Services.AddOryvaActiveMasterPolicy();
webBuilder.Services.AddOryvaRolePolicies();
await using (var webApp = webBuilder.Build())
{
    webApp.UseAuthentication();
    webApp.UseAuthorization();
    webApp.MapGet("/test/master", () => Microsoft.AspNetCore.Http.Results.Ok())
        .RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);
    webApp.MapGet("/test/admin", () => Results.Ok())
        .RequireAuthorization(OryvaRolePolicyExtensions.Admin);
    webApp.MapGet("/test/viewer", () => Results.Ok())
        .RequireAuthorization(OryvaRolePolicyExtensions.Viewer);
    await webApp.StartAsync();
    using var client = webApp.GetTestClient();
    async Task ExpectHttpAsync(string? subject, bool master, System.Net.HttpStatusCode expected)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/test/master");
        if (subject is not null)
        {
            request.Headers.Add("X-E2E-Subject", subject);
            if (master) request.Headers.Add("X-E2E-Master", "true");
        }
        using var response = await client.SendAsync(request);
        if (response.StatusCode != expected)
            throw new Exception($"HTTP policy expected {(int)expected}, got {(int)response.StatusCode} for {subject}");
    }
    await ExpectHttpAsync(null, false, System.Net.HttpStatusCode.Unauthorized);
    await ExpectHttpAsync(active.SubjectId, false, System.Net.HttpStatusCode.Forbidden);
    await ExpectHttpAsync("wrong-subject", true, System.Net.HttpStatusCode.Forbidden);
    await ExpectHttpAsync(active.SubjectId, true, System.Net.HttpStatusCode.OK);
    Console.WriteLine("PASS M2 HTTP middleware: 401 anonymous, 403 role/subject mismatch, 200 active master");
    async Task CheckRoleAsync(string route, string? role, System.Net.HttpStatusCode expected)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, route);
        if (role is not null)
        {
            request.Headers.Add("X-E2E-Subject", active.SubjectId);
            request.Headers.Add("X-E2E-Role", role);
        }
        using var response = await client.SendAsync(request);
        if (response.StatusCode != expected)
            throw new Exception($"M3 role policy {route}/{role ?? "anonymous"} expected {(int)expected}, got {(int)response.StatusCode}");
    }
    await CheckRoleAsync("/test/admin", null, System.Net.HttpStatusCode.Unauthorized);
    await CheckRoleAsync("/test/viewer", null, System.Net.HttpStatusCode.Unauthorized);
    await CheckRoleAsync("/test/admin", "viewer", System.Net.HttpStatusCode.Forbidden);
    await CheckRoleAsync("/test/admin", "master", System.Net.HttpStatusCode.Forbidden);
    await CheckRoleAsync("/test/admin", "admin", System.Net.HttpStatusCode.Forbidden);
    await CheckRoleAsync("/test/viewer", "viewer", System.Net.HttpStatusCode.Forbidden);
    await CheckRoleAsync("/test/viewer", "admin", System.Net.HttpStatusCode.Forbidden);
    await CheckRoleAsync("/test/viewer", "master", System.Net.HttpStatusCode.Forbidden);
    Console.WriteLine("PASS M3 HTTP role matrix: admin and viewer roles without active DB reservations denied");

    await webApp.StopAsync();
}

// The bootstrap intentionally leaves email unverified. For this isolated
// direct-grant E2E, finish the test identity's required actions via the
// restricted CI management service account. Never do this in production.
using (var adminHttp = new HttpClient())
{
    var adminTokenUrl = "http://127.0.0.1:8080/realms/oryva/protocol/openid-connect/token";
    using var adminGrant = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "client_credentials",
        ["client_id"] = "oryva-e2e-bootstrap",
        ["client_secret"] = secret
    });
    using var adminTokenResponse = await adminHttp.PostAsync(adminTokenUrl, adminGrant);
    adminTokenResponse.EnsureSuccessStatusCode();
    using var adminJson = System.Text.Json.JsonDocument.Parse(
        await adminTokenResponse.Content.ReadAsStringAsync());
    var adminAccessToken = adminJson.RootElement.GetProperty("access_token").GetString();
    var userUrl = "http://127.0.0.1:8080/admin/realms/oryva/users/" +
        Uri.EscapeDataString(active.SubjectId);
    using var getUser = new HttpRequestMessage(HttpMethod.Get, userUrl);
    getUser.Headers.Authorization =
        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminAccessToken);
    using var userResponse = await adminHttp.SendAsync(getUser);
    userResponse.EnsureSuccessStatusCode();
    using var userJson = System.Text.Json.JsonDocument.Parse(
        await userResponse.Content.ReadAsStringAsync());
    var required = userJson.RootElement.TryGetProperty("requiredActions", out var actions)
        ? actions.ToString() : "[]";
    Console.WriteLine("CI test master required actions before completion: " + required);
    using var update = new HttpRequestMessage(HttpMethod.Put, userUrl);
    update.Headers.Authorization =
        new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", adminAccessToken);
    update.Content = System.Net.Http.Json.JsonContent.Create(new
    {
        emailVerified = true,
        firstName = "E2E",
        lastName = "Master",
        requiredActions = Array.Empty<string>()
    });
    using var updateResponse = await adminHttp.SendAsync(update);
    updateResponse.EnsureSuccessStatusCode();
}

// Real Keycloak-issued JWT validation through the production bearer middleware.
// The E2E test client is configured with an audience mapper in setup_keycloak_e2e.py.
using (var tokenClient = new HttpClient())
{
    var tokenUrl = "http://127.0.0.1:8080/realms/oryva/protocol/openid-connect/token";
    using var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "password",
        ["client_id"] = "oryva-e2e-api",
        ["username"] = username,
        ["password"] = password
    });
    using var tokenResponse = await tokenClient.PostAsync(tokenUrl, tokenRequest);
    if (!tokenResponse.IsSuccessStatusCode)
        throw new Exception($"Keycloak test token grant failed ({(int)tokenResponse.StatusCode}): " +
            await tokenResponse.Content.ReadAsStringAsync());
    using var tokenJson = System.Text.Json.JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
    var token = tokenJson.RootElement.GetProperty("access_token").GetString()
        ?? throw new Exception("Keycloak returned no access token.");

    // Production requires HTTPS metadata. CI's Keycloak dev container is HTTP;
    // this E2E-only host overrides discovery transport, never production settings.
    var jwtBuilder = Microsoft.AspNetCore.Builder.WebApplication.CreateBuilder(
        new Microsoft.AspNetCore.Builder.WebApplicationOptions { EnvironmentName = "Development" });
    jwtBuilder.WebHost.UseTestServer();
    jwtBuilder.Services.AddSingleton(dataSource);
    jwtBuilder.Services.AddScoped<MasterReservationStore>();
    jwtBuilder.Services.AddOryvaKeycloakJwt(new OryvaJwtOptions
    {
        Issuer = "https://localhost/realms/oryva",
        Audience = "oryva-api"
    });
    jwtBuilder.Services.PostConfigure<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>(
        Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme,
        options =>
        {
            options.Authority = "http://127.0.0.1:8080/realms/oryva";
            options.MetadataAddress = "http://127.0.0.1:8080/realms/oryva/.well-known/openid-configuration";
            options.RequireHttpsMetadata = false;
            options.ConfigurationManager = new Microsoft.IdentityModel.Protocols.ConfigurationManager<Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfiguration>(
                options.MetadataAddress,
                new Microsoft.IdentityModel.Protocols.OpenIdConnect.OpenIdConnectConfigurationRetriever(),
                new Microsoft.IdentityModel.Protocols.HttpDocumentRetriever { RequireHttps = false });
            options.TokenValidationParameters.ValidIssuer = "http://127.0.0.1:8080/realms/oryva";
        });
    jwtBuilder.Services.AddOryvaActiveMasterPolicy();
    await using var jwtApp = jwtBuilder.Build();
    jwtApp.UseAuthentication();
    jwtApp.UseAuthorization();
    jwtApp.MapGet("/test/jwt-master", () => Results.Ok())
        .RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);
    await jwtApp.StartAsync();
    using var jwtHttp = jwtApp.GetTestClient();
    async Task<System.Net.HttpStatusCode> StatusAsync(string? bearer)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/test/jwt-master");
        if (bearer is not null)
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearer);
        using var response = await jwtHttp.SendAsync(request);
        return response.StatusCode;
    }
    if (await StatusAsync(null) != System.Net.HttpStatusCode.Unauthorized ||
        await StatusAsync(token + "tampered") != System.Net.HttpStatusCode.Unauthorized ||
        await StatusAsync(token) != System.Net.HttpStatusCode.OK)
        throw new Exception("Real Keycloak JWT HTTP authentication failed.");
    Console.WriteLine("PASS M2 real Keycloak JWT: anonymous/tampered denied, active master allowed");

    // CI-only: create a signed JWT with conflicting master/admin realm roles.
    using (var managementHttp = new HttpClient())
    {
        using var grant = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = "oryva-e2e-bootstrap",
            ["client_secret"] = secret
        });
        using var grantResponse = await managementHttp.PostAsync(tokenUrl, grant);
        grantResponse.EnsureSuccessStatusCode();
        using var grantJson = System.Text.Json.JsonDocument.Parse(
            await grantResponse.Content.ReadAsStringAsync());
        var managementToken = grantJson.RootElement.GetProperty("access_token").GetString();
        var roleUrl = "http://127.0.0.1:8080/admin/realms/oryva/roles/admin";
        using var roleRequest = new HttpRequestMessage(HttpMethod.Get, roleUrl);
        roleRequest.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", managementToken);
        using var roleResponse = await managementHttp.SendAsync(roleRequest);
        roleResponse.EnsureSuccessStatusCode();
        var rolePayload = await roleResponse.Content.ReadAsStringAsync();
        var mappingUrl = "http://127.0.0.1:8080/admin/realms/oryva/users/" +
            Uri.EscapeDataString(active.SubjectId) + "/role-mappings/realm";
        using (var assign = new HttpRequestMessage(HttpMethod.Post, mappingUrl))
        {
            assign.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", managementToken);
            assign.Content = new StringContent("[" + rolePayload + "]",
                System.Text.Encoding.UTF8, "application/json");
            using var assigned = await managementHttp.SendAsync(assign);
            assigned.EnsureSuccessStatusCode();
        }
        try
        {
            using var conflictingGrant = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["client_id"] = "oryva-e2e-api",
                ["username"] = username,
                ["password"] = password
            });
            using var conflictingResponse = await tokenClient.PostAsync(tokenUrl, conflictingGrant);
            conflictingResponse.EnsureSuccessStatusCode();
            using var conflictingJson = System.Text.Json.JsonDocument.Parse(
                await conflictingResponse.Content.ReadAsStringAsync());
            var conflictingToken =
                conflictingJson.RootElement.GetProperty("access_token").GetString();
            if (await StatusAsync(conflictingToken) != System.Net.HttpStatusCode.Unauthorized)
                throw new Exception("Signed master+admin Keycloak JWT must be rejected.");
            Console.WriteLine("PASS M3 real Keycloak JWT rejects conflicting master+admin roles");
        }
        finally
        {
            using var remove = new HttpRequestMessage(HttpMethod.Delete, mappingUrl);
            remove.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", managementToken);
            remove.Content = new StringContent("[" + rolePayload + "]",
                System.Text.Encoding.UTF8, "application/json");
            using var removed = await managementHttp.SendAsync(remove);
            removed.EnsureSuccessStatusCode();
        }
    }

    await jwtApp.StopAsync();
}
Console.WriteLine("PASS full .NET/Keycloak/PostgreSQL master bootstrap and recovery");

sealed class E2EAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-E2E-Subject", out var subject))
            return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new List<Claim> { new("sub", subject.ToString()) };
        if (Request.Headers.TryGetValue("X-E2E-Master", out var role) && role == "true")
            claims.Add(new Claim("oryva_realm_role", "master"));
        if (Request.Headers.TryGetValue("X-E2E-Role", out var ordinaryRole))
            claims.Add(new Claim("oryva_realm_role", ordinaryRole.ToString()));
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}
