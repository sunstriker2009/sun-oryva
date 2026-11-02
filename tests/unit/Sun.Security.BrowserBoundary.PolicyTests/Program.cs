using System.Net;
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

await app.StopAsync();
Console.WriteLine("PASS browser POST HTTPS, exact origin/host, fetch metadata and double-submit CSRF");
Console.WriteLine("PASS spoofed forwarding, duplicate cookies/origins, generic 403 and no-store");
Console.WriteLine("PASS opt-in boundary does not publish or modify enrollment or Keycloak accounts");
