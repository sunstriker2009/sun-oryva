using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Npgsql;
using Sun.Security.AspNetCore;
using Sun.Security.Bootstrap;

const string origin = "https://enroll.oryva.example";
var connectionString = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("Isolated CI database is required.");
var options = new NpgsqlConnectionStringBuilder(connectionString);
if (options.Host != "127.0.0.1" || options.Database != "oryva_e2e")
    throw new InvalidOperationException("Refusing to run against a non-CI database.");

await using var source = NpgsqlDataSource.Create(connectionString);
var invitations = new ViewerInvitationChallengeStore(source);
var sessions = new ViewerInvitationBrowserExchangeStore(source);
var lifecycle = new OryvaGuardedBrowserSessionLifecycle(sessions);
var viewer = Guid.NewGuid();
var username = "guarded-http-" + viewer.ToString("N")[..12];
var seededMaster = false;

try
{
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        INSERT INTO oryva.master_bootstrap
            (singleton_id, state, subject_id, activated_at)
        VALUES (1, 'active', 'ci-master', now());
        """, connection))
    {
        await command.ExecuteNonQueryAsync();
        seededMaster = true;
    }
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        INSERT INTO oryva.viewer_accounts
            (id, username, email, requested_by_subject, requested_by_role,
             keycloak_subject_id, state)
        VALUES (@id, @name, @email, 'ci-master', 'master', @subject, 'role_assigned');
        """, connection))
    {
        command.Parameters.AddWithValue("id", viewer);
        command.Parameters.AddWithValue("name", username);
        command.Parameters.AddWithValue("email", username + "@example.invalid");
        command.Parameters.AddWithValue("subject", "ci-guarded-" + viewer.ToString("N"));
        await command.ExecuteNonQueryAsync();
    }

    var invitation = await invitations.IssueAsync(viewer, "ci-master", "master");
    var initial = await sessions.ExchangeAsync(viewer, invitation.Token)
        ?? throw new Exception("Failed to seed a browser session.");

    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        EnvironmentName = "Development"
    });
    builder.WebHost.UseTestServer();
    await using var app = builder.Build();
    app.UseRouting();
    app.UseOryvaBrowserRequestGuard(origin);
    app.MapPost("/rotate", async (HttpContext ctx) =>
        await lifecycle.RotateAsync(ctx, viewer)
            ? Results.NoContent() : Results.StatusCode(403))
        .WithMetadata(new OryvaBrowserCeremonyAttribute());
    app.MapPost("/revoke", async (HttpContext ctx) =>
        await lifecycle.RevokeAsync(ctx, viewer)
            ? Results.NoContent() : Results.StatusCode(403))
        .WithMetadata(new OryvaBrowserCeremonyAttribute());
    await app.StartAsync();
    using var client = app.GetTestClient();
    var csrf = new string('A', 43); // Test-only CSRF fixture.

    async Task<HttpResponseMessage> PostAsync(
        string route, string bearer, string? suppliedOrigin = origin,
        string? suppliedCsrf = null, bool duplicate = false)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, origin + route);
        request.Headers.Host = "enroll.oryva.example";
        if (suppliedOrigin is not null)
            request.Headers.TryAddWithoutValidation("Origin", suppliedOrigin);
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "same-origin");
        if (suppliedCsrf is not null)
            request.Headers.TryAddWithoutValidation(OryvaBrowserRequestGuard.CsrfHeaderName, suppliedCsrf);
        var session = OryvaBrowserSessionCookie.Name + "=" + bearer;
        request.Headers.TryAddWithoutValidation("Cookie",
            OryvaBrowserRequestGuard.CsrfCookieName + "=" + csrf +
            "; " + session + (duplicate ? "; " + session : ""));
        return await client.SendAsync(request);
    }

    using (var denied = await PostAsync("/rotate", initial.BrowserSecret,
        "https://attacker.example", csrf))
    {
        if (denied.StatusCode != HttpStatusCode.Forbidden ||
            denied.Headers.Contains("Set-Cookie") ||
            !await sessions.IsLiveAsync(viewer, initial.BrowserSecret))
            throw new Exception("Cross-origin denial changed the live session.");
    }
    using (var denied = await PostAsync("/rotate", initial.BrowserSecret))
    {
        if (denied.StatusCode != HttpStatusCode.Forbidden ||
            !await sessions.IsLiveAsync(viewer, initial.BrowserSecret))
            throw new Exception("Missing CSRF invalidated the session.");
    }
    using (var denied = await PostAsync("/rotate", initial.BrowserSecret,
        origin, csrf, duplicate: true))
    {
        if (denied.StatusCode != HttpStatusCode.Forbidden ||
            !await sessions.IsLiveAsync(viewer, initial.BrowserSecret))
            throw new Exception("Duplicate bearer invalidated the session.");
    }

    using var rotatedResponse = await PostAsync("/rotate", initial.BrowserSecret, origin, csrf);
    if (rotatedResponse.StatusCode != HttpStatusCode.NoContent ||
        !rotatedResponse.Headers.TryGetValues("Set-Cookie", out var headers))
        throw new Exception("Guarded PostgreSQL rotation did not issue a cookie.");
    var cookie = headers.Single();
    var prefix = OryvaBrowserSessionCookie.Name + "=";
    if (!cookie.StartsWith(prefix, StringComparison.Ordinal) ||
        !cookie.Contains("httponly", StringComparison.OrdinalIgnoreCase) ||
        !cookie.Contains("secure", StringComparison.OrdinalIgnoreCase) ||
        !cookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase) ||
        cookie.Contains("domain=", StringComparison.OrdinalIgnoreCase))
        throw new Exception("Replacement cookie attributes are unsafe.");
    var replacement = cookie[prefix.Length..].Split(';', 2)[0];
    if (replacement == initial.BrowserSecret ||
        !await sessions.IsLiveAsync(viewer, replacement) ||
        await sessions.IsLiveAsync(viewer, initial.BrowserSecret))
        throw new Exception("Rotation failed to invalidate the old bearer.");

    using (var replay = await PostAsync("/rotate", initial.BrowserSecret, origin, csrf))
    {
        if (replay.StatusCode != HttpStatusCode.Forbidden ||
            replay.Headers.Contains("Set-Cookie"))
            throw new Exception("Stale bearer replay succeeded.");
    }

    using var revokedResponse = await PostAsync("/revoke", replacement, origin, csrf);
    if (revokedResponse.StatusCode != HttpStatusCode.NoContent ||
        !revokedResponse.Headers.TryGetValues("Set-Cookie", out var deleted) ||
        deleted.Count() != 2 ||
        await sessions.IsLiveAsync(viewer, replacement))
        throw new Exception("Revocation failed to clear both cookies and database bearer.");

    using (var replay = await PostAsync("/revoke", replacement, origin, csrf))
    {
        if (replay.StatusCode != HttpStatusCode.Forbidden ||
            replay.Headers.Contains("Set-Cookie"))
            throw new Exception("Revocation replay succeeded.");
    }

    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT state FROM oryva.viewer_accounts WHERE id = @viewer;
        """, connection))
    {
        command.Parameters.AddWithValue("viewer", viewer);
        if ((string?)await command.ExecuteScalarAsync() != "role_assigned")
            throw new Exception("Session lifecycle activated or modified the viewer.");
    }
    await app.StopAsync();
    Console.WriteLine("PASS guarded PostgreSQL/TestServer rotation, replay and revocation");
    Console.WriteLine("PASS origin/CSRF/duplicate-cookie denial, host-only cookie attributes");
    Console.WriteLine("PASS viewer remains role_assigned; no Keycloak activation");
}
finally
{
    await using var connection = await source.OpenConnectionAsync();
    await using (var cleanup = new NpgsqlCommand(
        "DELETE FROM oryva.viewer_accounts WHERE id = @viewer;", connection))
    {
        cleanup.Parameters.AddWithValue("viewer", viewer);
        await cleanup.ExecuteNonQueryAsync();
    }
    if (seededMaster)
    {
        await using var cleanup = new NpgsqlCommand(
            "DELETE FROM oryva.master_bootstrap WHERE singleton_id = 1 AND subject_id = 'ci-master';",
            connection);
        await cleanup.ExecuteNonQueryAsync();
    }
}
