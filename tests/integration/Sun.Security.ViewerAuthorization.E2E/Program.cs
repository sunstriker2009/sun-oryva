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


// Separate HTTP TestServer: exercises the actual ASP.NET Core rate-limiter
// middleware without modifying any Keycloak identity or production database.
var limitBuilder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    EnvironmentName = "Development"
});
limitBuilder.WebHost.UseTestServer();
limitBuilder.Services.AddAuthentication("E2EViewer")
    .AddScheme<AuthenticationSchemeOptions, ViewerTestAuthenticationHandler>(
        "E2EViewer", _ => { });
limitBuilder.Services.AddAuthorization();
limitBuilder.Services.AddOryvaManagementRateLimiting(2);
await using (var limitedApp = limitBuilder.Build())
{
    limitedApp.UseRouting();
    limitedApp.UseAuthentication();
    limitedApp.UseAuthorization();
    limitedApp.UseRateLimiter();
    limitedApp.MapPost("/test/write", () => Results.Ok())
        .RequireAuthorization()
        .RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);
    limitedApp.MapPost("/test/write-two", () => Results.Ok())
        .RequireAuthorization()
        .RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);
    limitedApp.MapGet("/test/read", () => Results.Ok())
        .RequireAuthorization();
    await limitedApp.StartAsync();
    using var limitedClient = limitedApp.GetTestClient();

    async Task<HttpResponseMessage> RequestAsync(
        HttpMethod method, string route, string? caller, string? forwarded = null)
    {
        using var request = new HttpRequestMessage(method, route);
        if (caller is not null) request.Headers.Add("X-Test-Subject", caller);
        if (forwarded is not null) request.Headers.Add("X-Forwarded-For", forwarded);
        return await limitedClient.SendAsync(request);
    }

    using (var anonymous = await RequestAsync(HttpMethod.Post, "/test/write", null))
        if (anonymous.StatusCode != HttpStatusCode.Unauthorized)
            throw new Exception("Unauthenticated management write was not denied.");
    using (var first = await RequestAsync(HttpMethod.Post, "/test/write", "manager-a"))
        if (first.StatusCode != HttpStatusCode.OK)
            throw new Exception("First management write was unexpectedly limited.");
    using (var second = await RequestAsync(HttpMethod.Post, "/test/write-two", "manager-a"))
        if (second.StatusCode != HttpStatusCode.OK)
            throw new Exception("Second management write was unexpectedly limited.");
    using (var rejected = await RequestAsync(
        HttpMethod.Post, "/test/write", "manager-a", "203.0.113.44"))
    {
        if (rejected.StatusCode != HttpStatusCode.TooManyRequests ||
            !(await rejected.Content.ReadAsStringAsync()).Contains(
                "management_rate_limit_exceeded", StringComparison.Ordinal) ||
            rejected.Headers.CacheControl?.NoStore != true)
            throw new Exception("Shared management write quota did not return a safe 429.");
    }
    using (var other = await RequestAsync(HttpMethod.Post, "/test/write", "manager-b"))
        if (other.StatusCode != HttpStatusCode.OK)
            throw new Exception("One manager exhausted another manager's quota.");
    using (var read = await RequestAsync(HttpMethod.Get, "/test/read", "manager-a"))
        if (read.StatusCode != HttpStatusCode.OK)
            throw new Exception("Read-only route should not consume write quota.");
    await limitedApp.StopAsync();
}
// Cross-replica quota uses PostgreSQL atomic UPSERT, not local memory.
// Two independent connection pools must share one subject's allowance.
await using (var secondSource = NpgsqlDataSource.Create(dsn))
{
    var quotaA = new OryvaDistributedManagementWriteQuota(source);
    var quotaB = new OryvaDistributedManagementWriteQuota(secondSource);
    var quotaSubject = "subject:quota-" + Guid.NewGuid().ToString("N");

    // Avoid a fixed-window boundary during the concurrent assertion.
    if (DateTimeOffset.UtcNow.Second >= 55)
        await Task.Delay(TimeSpan.FromSeconds(61 - DateTimeOffset.UtcNow.Second));
    var attempts = await Task.WhenAll(Enumerable.Range(0, 10).Select(i =>
        (i % 2 == 0 ? quotaA : quotaB).TryConsumeAsync(quotaSubject, 3)));
    if (attempts.Count(allowed => allowed) != 3 ||
        !await quotaB.TryConsumeAsync(quotaSubject + "-other", 3))
        throw new Exception("Concurrent API replicas exceeded the shared PostgreSQL quota.");
    Console.WriteLine("PASS atomic cross-replica management quota and subject isolation");

    var distributedBuilder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        EnvironmentName = "Development"
    });
    distributedBuilder.WebHost.UseTestServer();
    distributedBuilder.Services.AddSingleton(secondSource);
    distributedBuilder.Services.AddAuthentication("E2EViewer")
        .AddScheme<AuthenticationSchemeOptions, ViewerTestAuthenticationHandler>(
            "E2EViewer", _ => { });
    distributedBuilder.Services.AddAuthorization();
    distributedBuilder.Services.AddOryvaManagementRateLimiting(120);
    distributedBuilder.Services.AddOryvaDistributedManagementWriteQuota();
    await using (var distributedApp = distributedBuilder.Build())
    {
        distributedApp.UseRouting();
        distributedApp.UseAuthentication();
        distributedApp.UseAuthorization();
        distributedApp.UseRateLimiter();
        distributedApp.UseOryvaDistributedManagementWriteQuota(2);
        var handlerCalls = 0;
        distributedApp.MapPost("/test/distributed-write", () =>
            {
                handlerCalls++;
                return Results.Ok();
            })
            .RequireAuthorization()
            .RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);
        distributedApp.MapGet("/test/distributed-read", () => Results.Ok())
            .RequireAuthorization();
        await distributedApp.StartAsync();
        using var distributedClient = distributedApp.GetTestClient();
        var httpSubject = "quota-http-" + Guid.NewGuid().ToString("N");

        async Task<HttpResponseMessage> DistributedRequestAsync(
            HttpMethod method, string route, string? caller, string? forwarded = null)
        {
            using var request = new HttpRequestMessage(method, route);
            if (caller is not null) request.Headers.Add("X-Test-Subject", caller);
            if (forwarded is not null) request.Headers.Add("X-Forwarded-For", forwarded);
            return await distributedClient.SendAsync(request);
        }

        using (var anonymous = await DistributedRequestAsync(
            HttpMethod.Post, "/test/distributed-write", null))
            if (anonymous.StatusCode != HttpStatusCode.Unauthorized)
                throw new Exception("Anonymous write reached distributed quota middleware.");
        for (var i = 0; i < 2; i++)
        {
            using var allowed = await DistributedRequestAsync(
                HttpMethod.Post, "/test/distributed-write", httpSubject);
            if (allowed.StatusCode != HttpStatusCode.OK)
                throw new Exception("Valid distributed quota request was denied.");
        }
        using (var rejected = await DistributedRequestAsync(
            HttpMethod.Post, "/test/distributed-write", httpSubject, "203.0.113.2"))
        {
            if (rejected.StatusCode != HttpStatusCode.TooManyRequests ||
                rejected.Headers.CacheControl?.NoStore != true ||
                !(await rejected.Content.ReadAsStringAsync()).Contains(
                    "management_rate_limit_exceeded", StringComparison.Ordinal))
                throw new Exception("Exhausted distributed quota did not fail closed with 429.");
        }
        if (handlerCalls != 2)
            throw new Exception("Quota-rejected request reached the management handler.");
        using (var other = await DistributedRequestAsync(
            HttpMethod.Post, "/test/distributed-write", httpSubject + "-other"))
            if (other.StatusCode != HttpStatusCode.OK)
                throw new Exception("Distributed quota leaked across subjects.");
        using (var read = await DistributedRequestAsync(
            HttpMethod.Get, "/test/distributed-read", httpSubject))
            if (read.StatusCode != HttpStatusCode.OK)
                throw new Exception("Read-only endpoint unexpectedly consumed write quota.");
        await distributedApp.StopAsync();
    }
}
Console.WriteLine("PASS PostgreSQL management quota HTTP 429, handler rejection and read isolation");

// A database outage must reject management writes, not bypass the quota.
var unavailableBuilder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    EnvironmentName = "Development"
});
unavailableBuilder.WebHost.UseTestServer();
var unavailableDsn = new NpgsqlConnectionStringBuilder(dsn)
{
    Port = 1, Timeout = 1, Pooling = false
}.ConnectionString;
unavailableBuilder.Services.AddSingleton(NpgsqlDataSource.Create(unavailableDsn));
unavailableBuilder.Services.AddAuthentication("E2EViewer")
    .AddScheme<AuthenticationSchemeOptions, ViewerTestAuthenticationHandler>(
        "E2EViewer", _ => { });
unavailableBuilder.Services.AddAuthorization();
unavailableBuilder.Services.AddOryvaManagementRateLimiting(120);
unavailableBuilder.Services.AddOryvaDistributedManagementWriteQuota();
await using (var unavailableApp = unavailableBuilder.Build())
{
    unavailableApp.UseRouting();
    unavailableApp.UseAuthentication();
    unavailableApp.UseAuthorization();
    unavailableApp.UseRateLimiter();
    unavailableApp.UseOryvaDistributedManagementWriteQuota(2);
    var invoked = false;
    unavailableApp.MapPost("/test/write-unavailable", () =>
        {
            invoked = true;
            return Results.Ok();
        })
        .RequireAuthorization()
        .RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);
    await unavailableApp.StartAsync();
    using var unavailableClient = unavailableApp.GetTestClient();
    using var request = new HttpRequestMessage(HttpMethod.Post, "/test/write-unavailable");
    request.Headers.Add("X-Test-Subject", "offline-" + Guid.NewGuid().ToString("N"));
    using var response = await unavailableClient.SendAsync(request);
    if (response.StatusCode != HttpStatusCode.ServiceUnavailable ||
        invoked ||
        !(await response.Content.ReadAsStringAsync()).Contains(
            "management_quota_unavailable", StringComparison.Ordinal))
        throw new Exception("Unavailable quota database did not fail closed with 503.");
    await unavailableApp.StopAsync();
}
Console.WriteLine("PASS quota database outage denies management handler with safe 503");

var goodPrincipal = new ClaimsPrincipal(new ClaimsIdentity(
    [new Claim("sub", "subject-one")], "test"));
var duplicatePrincipal = new ClaimsPrincipal(new ClaimsIdentity(
    [new Claim("sub", "subject-one"), new Claim("sub", "subject-two")], "test"));
if (OryvaManagementRateLimiting.GetPartitionKey(goodPrincipal) != "subject:subject-one" ||
    OryvaManagementRateLimiting.GetPartitionKey(duplicatePrincipal) != "invalid-subject" ||
    OryvaManagementRateLimiting.GetPartitionKey(new ClaimsPrincipal()) != "invalid-subject")
    throw new Exception("Rate-limit partitioning must fail closed for ambiguous identities.");
foreach (var invalidLimit in new[] { 0, 121 })
{
    var rejected = false;
    try { new ServiceCollection().AddOryvaManagementRateLimiting(invalidLimit); }
    catch (ArgumentOutOfRangeException) { rejected = true; }
    if (!rejected) throw new Exception("Invalid management write limit was accepted.");
}
Console.WriteLine("PASS management HTTP write quota, isolation, read exclusion and fail-closed identity");

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
