using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Sun.Security.AspNetCore;

const string origin = "https://enroll.oryva.example";
var csrf = new string('A', 43); // Deterministic test-only shape; never a real token.

foreach (var invalid in new[]
{
    "http://enroll.oryva.example",
    "https://enroll.oryva.example/path",
    "https://user@enroll.oryva.example",
    "https://enroll.oryva.example?token=bad",
    "https://enroll.oryva.example#fragment",
    "https://enroll.oryva.example.",
    "not-an-origin"
})
{
    var rejected = false;
    try
    {
        var builder = WebApplication.CreateBuilder();
        await using var invalidApp = builder.Build();
        invalidApp.UseOryvaBrowserRequestGuard(invalid);
    }
    catch (ArgumentException) { rejected = true; }
    if (!rejected) throw new Exception("Invalid origin configuration was accepted.");
}

var appBuilder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    EnvironmentName = "Development"
});
appBuilder.WebHost.UseTestServer();
await using var app = appBuilder.Build();
app.UseRouting();
app.UseOryvaBrowserRequestGuard(origin);
var protectedCalls = 0;
var unmarkedCalls = 0;
app.MapPost("/ceremony", () =>
{
    protectedCalls++;
    return Results.Ok(new { status = "boundary_only" });
}).WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapGet("/csrf-bootstrap", OryvaBrowserCsrfBootstrap.CreateHandler(origin));
app.MapPost("/unmarked", () =>
{
    unmarkedCalls++;
    return Results.Ok();
});
await app.StartAsync();
using var client = app.GetTestClient();

async Task CheckAsync(
    string name, HttpStatusCode expected,
    string? suppliedOrigin = origin,
    string? suppliedCookie = null,
    string? suppliedCsrf = null,
    string? fetchSite = "same-origin",
    string scheme = "https",
    string host = "enroll.oryva.example",
    string route = "/ceremony",
    bool forwardedSpoof = false,
    bool duplicateOrigin = false)
{
    using var request = new HttpRequestMessage(
        HttpMethod.Post, scheme + "://" + host + route);
    request.Headers.Host = host;
    if (suppliedOrigin is not null)
    {
        request.Headers.TryAddWithoutValidation("Origin",
            duplicateOrigin ? new[] { suppliedOrigin, suppliedOrigin } : new[] { suppliedOrigin });
    }
    if (suppliedCookie is not null)
        request.Headers.TryAddWithoutValidation("Cookie", suppliedCookie);
    if (suppliedCsrf is not null)
        request.Headers.TryAddWithoutValidation(OryvaBrowserRequestGuard.CsrfHeaderName, suppliedCsrf);
    if (fetchSite is not null)
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", fetchSite);
    if (forwardedSpoof)
    {
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "enroll.oryva.example");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
        request.Headers.TryAddWithoutValidation("X-Forwarded-For", "127.0.0.1");
    }

    using var response = await client.SendAsync(request);
    if (response.StatusCode != expected)
        throw new Exception(name + ": expected " + expected + ", got " + response.StatusCode);
    if (route == "/ceremony")
    {
        if (response.Headers.CacheControl?.NoStore != true ||
            !response.Headers.TryGetValues("Referrer-Policy", out var policies) ||
            !policies.Contains("no-referrer"))
            throw new Exception(name + ": browser cache/referrer protections missing.");
        if (expected == HttpStatusCode.Forbidden)
        {
            var body = await response.Content.ReadAsStringAsync();
            if (!body.Contains("browser_request_rejected", StringComparison.Ordinal) ||
                body.Contains(csrf, StringComparison.Ordinal) ||
                body.Contains("enroll.oryva.example", StringComparison.Ordinal))
                throw new Exception(name + ": denied response leaked input or lacked generic error.");
        }
    }
}

var cookie = OryvaBrowserRequestGuard.CsrfCookieName + "=" + csrf;
await CheckAsync("valid request", HttpStatusCode.OK, suppliedCookie: cookie, suppliedCsrf: csrf);
await CheckAsync("forwarded headers ignored on valid request", HttpStatusCode.OK,
    suppliedCookie: cookie, suppliedCsrf: csrf, forwardedSpoof: true);
await CheckAsync("missing origin", HttpStatusCode.Forbidden,
    suppliedOrigin: null, suppliedCookie: cookie, suppliedCsrf: csrf);
await CheckAsync("null origin", HttpStatusCode.Forbidden,
    suppliedOrigin: "null", suppliedCookie: cookie, suppliedCsrf: csrf);
await CheckAsync("foreign origin", HttpStatusCode.Forbidden,
    suppliedOrigin: "https://attacker.example", suppliedCookie: cookie, suppliedCsrf: csrf);
await CheckAsync("same-site subdomain", HttpStatusCode.Forbidden,
    suppliedOrigin: "https://sub.enroll.oryva.example", suppliedCookie: cookie, suppliedCsrf: csrf);
await CheckAsync("duplicate origin", HttpStatusCode.Forbidden,
    suppliedCookie: cookie, suppliedCsrf: csrf, duplicateOrigin: true);
await CheckAsync("host mismatch", HttpStatusCode.Forbidden,
    suppliedCookie: cookie, suppliedCsrf: csrf, host: "attacker.example", forwardedSpoof: true);
await CheckAsync("downgraded scheme", HttpStatusCode.Forbidden,
    suppliedCookie: cookie, suppliedCsrf: csrf, scheme: "http", forwardedSpoof: true);
await CheckAsync("fetch metadata same-site", HttpStatusCode.Forbidden,
    suppliedCookie: cookie, suppliedCsrf: csrf, fetchSite: "same-site");
await CheckAsync("fetch metadata cross-site", HttpStatusCode.Forbidden,
    suppliedCookie: cookie, suppliedCsrf: csrf, fetchSite: "cross-site");
await CheckAsync("missing csrf header", HttpStatusCode.Forbidden, suppliedCookie: cookie);
await CheckAsync("missing csrf cookie", HttpStatusCode.Forbidden, suppliedCsrf: csrf);
await CheckAsync("wrong csrf", HttpStatusCode.Forbidden,
    suppliedCookie: cookie, suppliedCsrf: new string('B', 43));
await CheckAsync("short csrf", HttpStatusCode.Forbidden,
    suppliedCookie: cookie, suppliedCsrf: new string('A', 42));
await CheckAsync("duplicate csrf cookie", HttpStatusCode.Forbidden,
    suppliedCookie: cookie + "; " + cookie, suppliedCsrf: csrf);
await CheckAsync("unmarked endpoint unaffected", HttpStatusCode.OK,
    suppliedOrigin: null, fetchSite: null, route: "/unmarked");

if (protectedCalls != 2 || unmarkedCalls != 1)
    throw new Exception("A rejected browser request reached the endpoint handler.");

// The bootstrap route exists only in this isolated TestServer. No production
// route, browser session, credential grant or Keycloak activation is created.
async Task<HttpResponseMessage> BootstrapAsync(
    string scheme = "https", string host = "enroll.oryva.example",
    string? suppliedOrigin = null, string? fetchSite = "same-origin",
    bool sendHeader = true, bool duplicateHeader = false,
    bool forwardedSpoof = false, string query = "")
{
    using var request = new HttpRequestMessage(HttpMethod.Get,
        scheme + "://" + host + "/csrf-bootstrap" + query);
    request.Headers.Host = host;
    if (sendHeader)
        request.Headers.TryAddWithoutValidation(
            OryvaBrowserCsrfBootstrap.BootstrapHeaderName,
            duplicateHeader ? new[] { "1", "1" } : new[] { "1" });
    if (suppliedOrigin is not null)
        request.Headers.TryAddWithoutValidation("Origin", suppliedOrigin);
    if (fetchSite is not null)
        request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", fetchSite);
    if (forwardedSpoof)
    {
        request.Headers.TryAddWithoutValidation("X-Forwarded-Host", "enroll.oryva.example");
        request.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
    }
    return await client.SendAsync(request);
}

async Task ExpectBootstrapDeniedAsync(string name, HttpResponseMessage response)
{
    using (response)
    {
        if (response.StatusCode != HttpStatusCode.Forbidden ||
            response.Headers.Contains("Set-Cookie") ||
            response.Headers.CacheControl?.NoStore != true)
            throw new Exception(name + ": unsafe bootstrap denial.");
        var body = await response.Content.ReadAsStringAsync();
        if (!body.Contains("browser_request_rejected", StringComparison.Ordinal) ||
            body.Contains("csrfToken", StringComparison.Ordinal))
            throw new Exception(name + ": denial disclosed a token.");
    }
}

using var bootstrap1 = await BootstrapAsync();
if (bootstrap1.StatusCode != HttpStatusCode.OK ||
    bootstrap1.Headers.CacheControl?.NoStore != true ||
    !bootstrap1.Headers.TryGetValues("Set-Cookie", out var setCookies))
    throw new Exception("CSRF bootstrap missing cookie or cache protection.");
var issuedCookie = setCookies.Single();
using var document1 = JsonDocument.Parse(await bootstrap1.Content.ReadAsStringAsync());
var issuedToken = document1.RootElement.GetProperty("csrfToken").GetString()!;
if (issuedToken.Length != 43 ||
    !issuedCookie.StartsWith(OryvaBrowserRequestGuard.CsrfCookieName + "=" + issuedToken + ";",
        StringComparison.Ordinal) ||
    !issuedCookie.Contains("httponly", StringComparison.OrdinalIgnoreCase) ||
    !issuedCookie.Contains("secure", StringComparison.OrdinalIgnoreCase) ||
    !issuedCookie.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase) ||
    !issuedCookie.Contains("path=/", StringComparison.OrdinalIgnoreCase) ||
    !issuedCookie.Contains("max-age=300", StringComparison.OrdinalIgnoreCase) ||
    issuedCookie.Contains("domain=", StringComparison.OrdinalIgnoreCase))
    throw new Exception("CSRF bootstrap cookie violates __Host-/HttpOnly/TTL requirements.");

using var bootstrap2 = await BootstrapAsync(suppliedOrigin: origin);
using var document2 = JsonDocument.Parse(await bootstrap2.Content.ReadAsStringAsync());
var secondToken = document2.RootElement.GetProperty("csrfToken").GetString()!;
if (bootstrap2.StatusCode != HttpStatusCode.OK ||
    issuedToken == secondToken || secondToken.Length != 43)
    throw new Exception("CSRF bootstrap failed to mint independent random tokens.");

await CheckAsync("issued CSRF cookie passes POST guard", HttpStatusCode.OK,
    suppliedCookie: OryvaBrowserRequestGuard.CsrfCookieName + "=" + issuedToken,
    suppliedCsrf: issuedToken);
await CheckAsync("issued cookie with mismatched header denied", HttpStatusCode.Forbidden,
    suppliedCookie: OryvaBrowserRequestGuard.CsrfCookieName + "=" + issuedToken,
    suppliedCsrf: secondToken);
if (protectedCalls != 3)
    throw new Exception("CSRF bootstrap bypassed the opt-in POST guard.");

await ExpectBootstrapDeniedAsync("missing custom header",
    await BootstrapAsync(sendHeader: false));
await ExpectBootstrapDeniedAsync("duplicate custom header",
    await BootstrapAsync(duplicateHeader: true));
await ExpectBootstrapDeniedAsync("foreign origin",
    await BootstrapAsync(suppliedOrigin: "https://attacker.example"));
await ExpectBootstrapDeniedAsync("same-site subdomain",
    await BootstrapAsync(suppliedOrigin: "https://sub.enroll.oryva.example"));
await ExpectBootstrapDeniedAsync("cross-site metadata",
    await BootstrapAsync(fetchSite: "cross-site"));
await ExpectBootstrapDeniedAsync("same-site metadata",
    await BootstrapAsync(fetchSite: "same-site"));
await ExpectBootstrapDeniedAsync("downgraded HTTP",
    await BootstrapAsync(scheme: "http", forwardedSpoof: true));
await ExpectBootstrapDeniedAsync("spoofed forwarded host",
    await BootstrapAsync(host: "attacker.example", forwardedSpoof: true));
await ExpectBootstrapDeniedAsync("query parameters forbidden",
    await BootstrapAsync(query: "?token=should-not-be-here"));

foreach (var invalid in new[] { "http://enroll.oryva.example",
    "https://enroll.oryva.example/path", "https://attacker@example.com" })
{
    try
    {
        _ = OryvaBrowserCsrfBootstrap.CreateHandler(invalid);
        throw new Exception("Invalid CSRF bootstrap origin was accepted.");
    }
    catch (ArgumentException) { }
}

Console.WriteLine("PASS opt-in CSRF bootstrap: 256-bit unique token, HttpOnly __Host- cookie, five-minute TTL");
Console.WriteLine("PASS isolated browser bootstrap GET, origin/host/metadata/HTTPS denial and POST guard round-trip");

await app.StopAsync();
Console.WriteLine("PASS browser POST HTTPS, exact origin/host, fetch metadata and double-submit CSRF");
Console.WriteLine("PASS spoofed forwarding, duplicate cookies/origins, generic 403 and no-store");
Console.WriteLine("PASS opt-in boundary does not publish or modify enrollment or Keycloak accounts");
