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
    // A well-shaped cookie must never authorize a different viewer, even when
    // the HTTP guard and CSRF token are valid.
    app.MapPost("/rotate/wrong-viewer", async (HttpContext ctx) =>
        await lifecycle.RotateAsync(ctx, Guid.NewGuid())
            ? Results.NoContent() : Results.StatusCode(403))
        .WithMetadata(new OryvaBrowserCeremonyAttribute());
    app.MapPost("/revoke/wrong-viewer", async (HttpContext ctx) =>
        await lifecycle.RevokeAsync(ctx, Guid.NewGuid())
            ? Results.NoContent() : Results.StatusCode(403))
        .WithMetadata(new OryvaBrowserCeremonyAttribute());
    // A response that has already started must not consume or revoke the
    // database bearer, because a replacement/clearing cookie cannot be sent.
    app.MapPost("/rotate/response-started", async (HttpContext ctx) =>
    {
        await ctx.Response.WriteAsync("started");
        if (await lifecycle.RotateAsync(ctx, viewer))
            throw new Exception("Started response rotated a browser bearer.");
    }).WithMetadata(new OryvaBrowserCeremonyAttribute());
    app.MapPost("/revoke/response-started", async (HttpContext ctx) =>
    {
        await ctx.Response.WriteAsync("started");
        if (await lifecycle.RevokeAsync(ctx, viewer))
            throw new Exception("Started response revoked a browser bearer.");
    }).WithMetadata(new OryvaBrowserCeremonyAttribute());
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

    foreach (var wrongViewerRoute in new[]
    {
        "/rotate/wrong-viewer", "/revoke/wrong-viewer"
    })
    {
        using var denied = await PostAsync(
            wrongViewerRoute, initial.BrowserSecret, origin, csrf);
        if (denied.StatusCode != HttpStatusCode.Forbidden ||
            denied.Headers.Contains("Set-Cookie") ||
            !await sessions.IsLiveAsync(viewer, initial.BrowserSecret))
            throw new Exception("Cross-viewer session mutation was permitted.");
    }

    foreach (var startedRoute in new[]
    {
        "/rotate/response-started", "/revoke/response-started"
    })
    {
        using var started = await PostAsync(startedRoute, initial.BrowserSecret, origin, csrf);
        if (started.StatusCode != HttpStatusCode.OK ||
            await started.Content.ReadAsStringAsync() != "started" ||
            started.Headers.Contains("Set-Cookie") ||
            !await sessions.IsLiveAsync(viewer, initial.BrowserSecret))
            throw new Exception("Started response mutated or disclosed the live session.");
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

    // HTTP-level contention: exactly one request may rotate a given bearer.
    // Each request has its own HttpRequestMessage; the store serializes the
    // digest transition and audit transaction in PostgreSQL.
    var contenders = await Task.WhenAll(Enumerable.Range(0, 16)
        .Select(_ => PostAsync("/rotate", replacement, origin, csrf)));
    string? winningBearer = null;
    try
    {
        var winners = contenders.Where(r => r.StatusCode == HttpStatusCode.NoContent).ToArray();
        if (winners.Length != 1 ||
            contenders.Count(r => r.StatusCode == HttpStatusCode.Forbidden) != 15 ||
            contenders.Where(r => r.StatusCode == HttpStatusCode.Forbidden)
                .Any(r => r.Headers.Contains("Set-Cookie")))
            throw new Exception("Concurrent HTTP rotation allowed replay or disclosed cookies.");

        var winnerCookies = winners[0].Headers.GetValues("Set-Cookie").ToArray();
        if (winnerCookies.Length != 1 ||
            !winnerCookies[0].StartsWith(prefix, StringComparison.Ordinal))
            throw new Exception("Concurrent winner did not receive one replacement cookie.");
        winningBearer = winnerCookies[0][prefix.Length..].Split(';', 2)[0];
        if (winningBearer == replacement ||
            !await sessions.IsLiveAsync(viewer, winningBearer) ||
            await sessions.IsLiveAsync(viewer, replacement))
            throw new Exception("Concurrent rotation did not preserve one live bearer.");
    }
    finally
    {
        foreach (var response in contenders) response.Dispose();
    }

    // Revoke the sole successful concurrent rotation's bearer.
    replacement = winningBearer
        ?? throw new Exception("Concurrent rotation winner was not captured.");

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
    Console.WriteLine("PASS guarded PostgreSQL/TestServer rotation, 16-way HTTP contention, replay and revocation");
    Console.WriteLine("PASS origin/CSRF/duplicate-cookie/cross-viewer denial, host-only cookie attributes");
    Console.WriteLine("PASS viewer remains role_assigned; no Keycloak activation");
}
finally
{
    await using var connection = await source.OpenConnectionAsync();
    // Match existing invitation E2E cleanup order to satisfy foreign keys.
    foreach (var sql in new[]
    {
        "DELETE FROM oryva.viewer_invitation_browser_sessions WHERE viewer_id = @viewer;",
        """
        DELETE FROM oryva.viewer_invitation_outbox
        WHERE challenge_id IN
            (SELECT id FROM oryva.viewer_invitation_challenges WHERE viewer_id = @viewer);
        """,
        "DELETE FROM oryva.viewer_invitation_challenges WHERE viewer_id = @viewer;",
        "DELETE FROM oryva.viewer_accounts WHERE id = @viewer;"
    })
    {
        await using var cleanup = new NpgsqlCommand(sql, connection);
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
