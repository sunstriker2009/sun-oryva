using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Npgsql;
using Sun.Security.AspNetCore;
using Sun.Security.Bootstrap;

var dsn = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("Missing ORYVA_TEST_DATABASE_URL.");
await using var source = NpgsqlDataSource.Create(dsn);
var id = Guid.NewGuid();
var username = "viewer-e2e-" + id.ToString("N")[..12];
var email = username + "@example.invalid";
var subject = "viewer-subject-" + Guid.NewGuid().ToString("N");

// SQL-only fixture: no Keycloak viewer account is enabled by this test.
// Production viewer activation must independently verify Keycloak ownership.
await using (var connection = await source.OpenConnectionAsync())
await using (var insert = new NpgsqlCommand("""
    INSERT INTO oryva.viewer_accounts
        (id, username, email, requested_by_subject, requested_by_role)
    VALUES (@id, @username, @email, 'test-master', 'master');
    """, connection))
{
    insert.Parameters.AddWithValue("id", id);
    insert.Parameters.AddWithValue("username", username);
    insert.Parameters.AddWithValue("email", email);
    if (await insert.ExecuteNonQueryAsync() != 1)
        throw new Exception("Viewer reservation fixture failed.");
}

var viewers = new ActiveViewerAuthorization(new ViewerAccountStore(source));
if (await viewers.IsActiveViewerSubjectAsync(subject, true) ||
    await viewers.IsActiveViewerSubjectAsync(subject, false) ||
    await viewers.IsActiveViewerSubjectAsync(null, true))
    throw new Exception("Reserved or missing viewer subject was authorized.");

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    EnvironmentName = "Development"
});
builder.WebHost.UseTestServer();
builder.Services.AddSingleton(source);
builder.Services.AddScoped<AdminProvisioningStore>();
builder.Services.AddAuthentication("E2EViewer")
    .AddScheme<AuthenticationSchemeOptions, ViewerTestAuthenticationHandler>(
        "E2EViewer", _ => { });
builder.Services.AddOryvaRolePolicies();
await using var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/test/viewer", () => Results.Ok())
    .RequireAuthorization(OryvaRolePolicyExtensions.Viewer);
app.MapGet("/test/admin", () => Results.Ok())
    .RequireAuthorization(OryvaRolePolicyExtensions.Admin);
await app.StartAsync();
using var client = app.GetTestClient();

async Task ExpectAsync(string route, string? tokenSubject, string? role, HttpStatusCode expected)
{
    using var request = new HttpRequestMessage(HttpMethod.Get, route);
    if (tokenSubject is not null)
        request.Headers.Add("X-Test-Subject", tokenSubject);
    if (role is not null)
        request.Headers.Add("X-Test-Role", role);
    using var response = await client.SendAsync(request);
    if (response.StatusCode != expected)
        throw new Exception(
            $"{route}: expected {(int)expected}, got {(int)response.StatusCode}.");
}

await ExpectAsync("/test/viewer", null, null, HttpStatusCode.Unauthorized);
await ExpectAsync("/test/viewer", subject, "viewer", HttpStatusCode.Forbidden);
await ExpectAsync("/test/viewer", subject, "admin", HttpStatusCode.Forbidden);
await ExpectAsync("/test/admin", subject, "viewer", HttpStatusCode.Forbidden);
Console.WriteLine("PASS reserved viewer and role-only claims fail closed");

await using (var connection = await source.OpenConnectionAsync())
await using (var activate = new NpgsqlCommand("""
    UPDATE oryva.viewer_accounts
    SET keycloak_subject_id = @subject, state = 'active', updated_at = now()
    WHERE id = @id AND state = 'reserved';
    """, connection))
{
    activate.Parameters.AddWithValue("id", id);
    activate.Parameters.AddWithValue("subject", subject);
    if (await activate.ExecuteNonQueryAsync() != 1)
        throw new Exception("Viewer activation test fixture failed.");
}
if (!await viewers.IsActiveViewerSubjectAsync(subject, true) ||
    await viewers.IsActiveViewerSubjectAsync(subject, false))
    throw new Exception("Active viewer database gate failed.");

await ExpectAsync("/test/viewer", subject, "viewer", HttpStatusCode.OK);
await ExpectAsync("/test/viewer", "different-subject", "viewer", HttpStatusCode.Forbidden);
await ExpectAsync("/test/viewer", subject, "master", HttpStatusCode.Forbidden);
await ExpectAsync("/test/viewer", subject, "viewer,admin", HttpStatusCode.Forbidden);
await ExpectAsync("/test/admin", subject, "viewer", HttpStatusCode.Forbidden);
await ExpectAsync("/test/admin", subject, "admin", HttpStatusCode.Forbidden);
Console.WriteLine("PASS active viewer requires exclusive role and exact DB subject");

await using (var connection = await source.OpenConnectionAsync())
await using (var deactivate = new NpgsqlCommand("""
    UPDATE oryva.viewer_accounts
    SET state = 'deactivated', updated_at = now()
    WHERE id = @id AND state = 'active';
    """, connection))
{
    deactivate.Parameters.AddWithValue("id", id);
    if (await deactivate.ExecuteNonQueryAsync() != 1)
        throw new Exception("Viewer deactivation test fixture failed.");
}
await ExpectAsync("/test/viewer", subject, "viewer", HttpStatusCode.Forbidden);
if (await viewers.IsActiveViewerSubjectAsync(subject, true))
    throw new Exception("Revoked viewer still authorizes.");
Console.WriteLine("PASS database revocation immediately denies previously valid viewer claims");
await app.StopAsync();

sealed class ViewerTestAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Test-Subject", out var subject))
            return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new List<Claim> { new("sub", subject.ToString()) };
        if (Request.Headers.TryGetValue("X-Test-Role", out var role))
        {
            foreach (var value in role.ToString().Split(','))
                claims.Add(new Claim("oryva_realm_role", value));
        }
        var identity = new ClaimsIdentity(claims, Scheme.Name);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}
