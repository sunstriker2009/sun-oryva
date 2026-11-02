using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using Sun.Security.AspNetCore;

var connectionString = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("ORYVA_TEST_DATABASE_URL is required.");
var options = new NpgsqlConnectionStringBuilder(connectionString);
if (options.Host != "127.0.0.1" || options.Database != "oryva_e2e")
    throw new InvalidOperationException("Browser admission E2E requires isolated loopback CI PostgreSQL.");

await using var source = NpgsqlDataSource.Create(connectionString);
var testKey = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray(); // CI-only, never deploy.
var quota = new OryvaBrowserAdmissionQuota(source, testKey);

async Task ResetAsync()
{
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand(
        "DELETE FROM oryva.browser_admission_quotas;", connection);
    await command.ExecuteNonQueryAsync();
}
async Task<int> CountAsync(string scope)
{
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand(
        "SELECT count(*) FROM oryva.browser_admission_quotas WHERE scope = @scope;",
        connection);
    command.Parameters.AddWithValue("scope", scope);
    return Convert.ToInt32(await command.ExecuteScalarAsync());
}
async Task<int> CounterAsync(string scope)
{
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand(
        "SELECT request_count FROM oryva.browser_admission_quotas WHERE scope = @scope LIMIT 1;",
        connection);
    command.Parameters.AddWithValue("scope", scope);
    return Convert.ToInt32(await command.ExecuteScalarAsync());
}

try
{
    await ResetAsync();
    var ip = IPAddress.Parse("198.51.100.25");
    var results = await Task.WhenAll(Enumerable.Range(0, 48)
        .Select(_ => quota.TryConsumeAsync(ip, 12, 200)));
    if (results.Count(x => x) != 12 ||
        await CounterAsync("ip") != 13 ||
        await CounterAsync("global") != 48 ||
        await CountAsync("ip") != 1)
        throw new Exception("Cross-replica same-IP quota did not serialize/saturate.");

    // IPv4-mapped addresses cannot bypass the IPv4 partition.
    if (await quota.TryConsumeAsync(IPAddress.Parse("::ffff:198.51.100.25"), 12, 200))
        throw new Exception("IPv4-mapped address bypassed quota.");

    await ResetAsync();
    var diverse = await Task.WhenAll(Enumerable.Range(1, 48)
        .Select(i => quota.TryConsumeAsync(IPAddress.Parse("203.0.113." + i), 100, 25)));
    if (diverse.Count(x => x) != 25 ||
        await CounterAsync("global") != 26 ||
        await CountAsync("ip") != 48)
        throw new Exception("Global quota failed under distinct-source concurrency.");

    // HMAC keys are opaque, not plaintext or unkeyed IP strings.
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT partition_key FROM oryva.browser_admission_quotas WHERE scope = 'ip';
        """, connection))
    await using (var reader = await command.ExecuteReaderAsync())
    {
        while (await reader.ReadAsync())
        {
            var value = reader.GetString(0);
            if (value.Length != 64 || value.Contains("203.0.113", StringComparison.Ordinal))
                throw new Exception("IP address persisted in quota key.");
        }
    }

    await ResetAsync();
    if (!await quota.TryConsumeAsync(IPAddress.Parse("2001:db8:abcd:1234::1"), 1, 10) ||
        await quota.TryConsumeAsync(IPAddress.Parse("2001:db8:abcd:1234::ffff"), 1, 10))
        throw new Exception("IPv6 /64 aggregation failed.");

    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        UPDATE oryva.browser_admission_quotas
        SET window_start = clock_timestamp() - interval '2 minutes';
        """, connection))
        await command.ExecuteNonQueryAsync();
    if (!await quota.TryConsumeAsync(IPAddress.Parse("2001:db8:abcd:1234::2"), 1, 10))
        throw new Exception("PostgreSQL quota window did not recover.");

    var invalidKeyRejected = false;
    try { _ = new OryvaBrowserAdmissionQuota(source, new byte[32]); }
    catch (ArgumentException) { invalidKeyRejected = true; }
    if (!invalidKeyRejected)
        throw new Exception("Predictable all-zero HMAC key accepted.");

    // Isolated HTTP host: X-CI-Remote is a test-only fixture, not production
    // forwarding behavior. Production middleware reads ONLY RemoteIpAddress.
    await ResetAsync();
    var builder = WebApplication.CreateBuilder(new WebApplicationOptions
    {
        EnvironmentName = "Development"
    });
    builder.WebHost.UseTestServer();
    builder.Services.AddSingleton(source);
    builder.Services.AddOryvaBrowserAdmissionQuota(testKey);
    await using var app = builder.Build();
    app.UseRouting();
    app.Use(async (ctx, next) =>
    {
        if (ctx.Request.Headers.TryGetValue("X-CI-Remote", out var fixtureIp) &&
            IPAddress.TryParse(fixtureIp.ToString(), out var parsed))
            ctx.Connection.RemoteIpAddress = parsed;
        await next();
    });
    app.UseOryvaBrowserAdmissionQuota(2, 20);
    var protectedCalls = 0;
    var unmarkedCalls = 0;
    app.MapPost("/ceremony", () =>
    {
        protectedCalls++;
        return Results.Ok();
    }).WithMetadata(new OryvaBrowserCeremonyAttribute());
    app.MapPost("/unmarked", () =>
    {
        unmarkedCalls++;
        return Results.Ok();
    });
    await app.StartAsync();
    using var client = app.GetTestClient();

    async Task<HttpResponseMessage> SendAsync(string path, string? remote,
        string? forwarded = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post,
            "https://enroll.oryva.example" + path);
        if (remote is not null)
            request.Headers.TryAddWithoutValidation("X-CI-Remote", remote);
        if (forwarded is not null)
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", forwarded);
        return await client.SendAsync(request);
    }

    using (var one = await SendAsync("/ceremony", "198.51.100.55", "203.0.113.10"))
    using (var two = await SendAsync("/ceremony", "198.51.100.55", "203.0.113.11"))
    using (var three = await SendAsync("/ceremony", "198.51.100.55", "203.0.113.12"))
    using (var unmarked = await SendAsync("/unmarked", null))
    {
        if (one.StatusCode != HttpStatusCode.OK ||
            two.StatusCode != HttpStatusCode.OK ||
            three.StatusCode != HttpStatusCode.TooManyRequests ||
            unmarked.StatusCode != HttpStatusCode.OK ||
            protectedCalls != 2 || unmarkedCalls != 1 ||
            three.Headers.CacheControl?.NoStore != true ||
            !three.Headers.Contains("Retry-After"))
            throw new Exception("HTTP admission boundary, forwarding isolation or 429 failed.");
        var denied = await three.Content.ReadAsStringAsync();
        if (!denied.Contains("browser_admission_rejected", StringComparison.Ordinal) ||
            denied.Contains("198.51.100", StringComparison.Ordinal))
            throw new Exception("Admission rejection leaked source identity.");
    }

    // TestServer leaves the connection address null unless the fixture sets it.
    using (var missingIp = await SendAsync("/ceremony", null))
    {
        if (missingIp.StatusCode != HttpStatusCode.ServiceUnavailable)
            throw new Exception("Missing trusted client address was not fail-closed.");
    }

    Console.WriteLine("PASS PostgreSQL 48-way per-IP and global contention, saturation and rollover");
    Console.WriteLine("PASS keyed IP non-disclosure, IPv4 mapping and IPv6 /64 partitioning");
    Console.WriteLine("PASS HTTP 429, forwarded-header spoof resistance, 503 and endpoint isolation");
}
finally
{
    await ResetAsync();
}
