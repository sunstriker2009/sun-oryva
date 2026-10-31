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
webBuilder.Services.AddAuthentication("E2E")
    .AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions,
        E2EAuthenticationHandler>("E2E", _ => { });
webBuilder.Services.AddOryvaActiveMasterPolicy();
await using (var webApp = webBuilder.Build())
{
    webApp.UseAuthentication();
    webApp.UseAuthorization();
    webApp.MapGet("/test/master", () => Microsoft.AspNetCore.Http.Results.Ok())
        .RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);
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
    await webApp.StopAsync();
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
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}
