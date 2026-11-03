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

var browserBearerOne = new string('C', 43); // Test-only; not a real browser secret.
var browserBearerTwo = new string('D', 43);
app.MapPost("/session/issue", (HttpContext context) =>
    OryvaBrowserSessionCookie.TryIssue(context, browserBearerOne,
        DateTimeOffset.UtcNow.AddMinutes(4))
        ? Results.NoContent() : Results.StatusCode(403))
    .WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapPost("/session/replace", (HttpContext context) =>
    OryvaBrowserSessionCookie.TryIssue(context, browserBearerTwo,
        DateTimeOffset.UtcNow.AddMinutes(3))
        ? Results.NoContent() : Results.StatusCode(403))
    .WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapPost("/session/expired", (HttpContext context) =>
    OryvaBrowserSessionCookie.TryIssue(context, browserBearerOne,
        DateTimeOffset.UtcNow.AddSeconds(-1))
        ? Results.NoContent() : Results.StatusCode(403))
    .WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapPost("/session/overlong", (HttpContext context) =>
    OryvaBrowserSessionCookie.TryIssue(context, browserBearerOne,
        DateTimeOffset.UtcNow.AddMinutes(6))
        ? Results.NoContent() : Results.StatusCode(403))
    .WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapPost("/session/read", (HttpContext context) =>
    OryvaBrowserSessionCookie.TryReadUntrustedBearer(context, out _)
        ? Results.NoContent() : Results.BadRequest())
    .WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapPost("/session/clear", (HttpContext context) =>
    OryvaBrowserSessionCookie.TryClear(context)
        ? Results.NoContent() : Results.StatusCode(403))
    .WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapPost("/session/unmarked", (HttpContext context) =>
    OryvaBrowserSessionCookie.TryIssue(context, browserBearerOne,
        DateTimeOffset.UtcNow.AddMinutes(4))
        ? Results.NoContent() : Results.StatusCode(403));

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


async Task<HttpResponseMessage> SessionPostAsync(
    string path, string? bearer = null, bool duplicate = false,
    string? suppliedOrigin = origin, string suppliedCsrf = csrf)
{
    using var request = new HttpRequestMessage(
        HttpMethod.Post, origin + path);
    request.Headers.Host = "enroll.oryva.example";
    if (suppliedOrigin is not null)
        request.Headers.TryAddWithoutValidation("Origin", suppliedOrigin);
    request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "same-origin");
    request.Headers.TryAddWithoutValidation(
        OryvaBrowserRequestGuard.CsrfHeaderName, suppliedCsrf);
    var cookies = OryvaBrowserRequestGuard.CsrfCookieName + "=" + csrf;
    if (bearer is not null)
    {
        var session = OryvaBrowserSessionCookie.Name + "=" + bearer;
        cookies += "; " + session;
        if (duplicate) cookies += "; " + session;
    }
    request.Headers.TryAddWithoutValidation("Cookie", cookies);
    return await client.SendAsync(request);
}

using (var issued = await SessionPostAsync("/session/issue"))
{
    if (issued.StatusCode != HttpStatusCode.NoContent ||
        issued.Headers.CacheControl?.NoStore != true ||
        !issued.Headers.TryGetValues("Set-Cookie", out var values))
        throw new Exception("Guarded browser session cookie was not issued securely.");
    var issuedCookies = values.ToArray();
    if (issuedCookies.Length != 1)
        throw new Exception("Unexpected additional browser cookie.");
    var c = issuedCookies[0];
    if (!c.StartsWith(OryvaBrowserSessionCookie.Name + "=" + browserBearerOne + ";",
            StringComparison.Ordinal) ||
        !c.Contains("httponly", StringComparison.OrdinalIgnoreCase) ||
        !c.Contains("secure", StringComparison.OrdinalIgnoreCase) ||
        !c.Contains("samesite=strict", StringComparison.OrdinalIgnoreCase) ||
        !c.Contains("path=/", StringComparison.OrdinalIgnoreCase) ||
        !c.Contains("max-age=", StringComparison.OrdinalIgnoreCase) ||
        !c.Contains("expires=", StringComparison.OrdinalIgnoreCase) ||
        c.Contains("domain=", StringComparison.OrdinalIgnoreCase) ||
        (await issued.Content.ReadAsStringAsync()).Contains(browserBearerOne,
            StringComparison.Ordinal))
        throw new Exception("Browser bearer cookie attributes or redaction violated.");
}
using (var replaced = await SessionPostAsync("/session/replace", browserBearerOne))
{
    if (replaced.StatusCode != HttpStatusCode.NoContent ||
        !replaced.Headers.TryGetValues("Set-Cookie", out var values) ||
        !values.Single().StartsWith(OryvaBrowserSessionCookie.Name + "=" +
            browserBearerTwo + ";", StringComparison.Ordinal))
        throw new Exception("Browser bearer replacement cookie missing.");
}
foreach (var path in new[] { "/session/expired", "/session/overlong" })
{
    using var denied = await SessionPostAsync(path);
    if (denied.StatusCode != HttpStatusCode.Forbidden ||
        denied.Headers.Contains("Set-Cookie"))
        throw new Exception("Invalid database expiry minted a browser bearer.");
}
using (var read = await SessionPostAsync("/session/read", browserBearerTwo))
{
    if (read.StatusCode != HttpStatusCode.NoContent)
        throw new Exception("Well-shaped untrusted browser cookie not parsed.");
}
foreach (var (bearer, duplicate) in new (string?, bool)[]
{
    (null, false), ("short", false), (browserBearerTwo, true)
})
{
    using var denied = await SessionPostAsync("/session/read", bearer, duplicate);
    if (denied.StatusCode != HttpStatusCode.BadRequest)
        throw new Exception("Missing, malformed or duplicate browser cookie accepted.");
}
using (var foreign = await SessionPostAsync("/session/issue",
    suppliedOrigin: "https://attacker.example"))
{
    if (foreign.StatusCode != HttpStatusCode.Forbidden ||
        foreign.Headers.Contains("Set-Cookie"))
        throw new Exception("Cross-origin request issued a browser bearer.");
}
using (var unmarked = await SessionPostAsync("/session/unmarked"))
{
    if (unmarked.StatusCode != HttpStatusCode.Forbidden ||
        unmarked.Headers.Contains("Set-Cookie"))
        throw new Exception("Unmarked endpoint bypassed guarded cookie issuance.");
}
using (var cleared = await SessionPostAsync("/session/clear", browserBearerTwo))
{
    if (cleared.StatusCode != HttpStatusCode.NoContent ||
        cleared.Headers.CacheControl?.NoStore != true ||
        !cleared.Headers.TryGetValues("Set-Cookie", out var values))
        throw new Exception("Guarded cookie clearing failed.");
    var deleted = values.ToArray();
    foreach (var name in new[] { OryvaBrowserSessionCookie.Name,
        OryvaBrowserRequestGuard.CsrfCookieName })
    {
        if (!deleted.Any(c => c.StartsWith(name + "=", StringComparison.Ordinal) &&
            c.Contains("expires=", StringComparison.OrdinalIgnoreCase) &&
            c.Contains("path=/", StringComparison.OrdinalIgnoreCase) &&
            !c.Contains("domain=", StringComparison.OrdinalIgnoreCase)))
            throw new Exception("Browser or CSRF cookie was not cleared host-only.");
    }
}
Console.WriteLine("PASS opt-in guarded browser bearer issue, replacement, expiry cap and clearing");
Console.WriteLine("PASS cookie duplicate rejection, origin/CSRF boundary, no-store and non-disclosure");
Console.WriteLine("PASS cookie parsing alone does not authenticate or activate a viewer");

await app.StopAsync();
Console.WriteLine("PASS browser POST HTTPS, exact origin/host, fetch metadata and double-submit CSRF");
Console.WriteLine("PASS spoofed forwarding, duplicate cookies/origins, generic 403 and no-store");
Console.WriteLine("PASS opt-in boundary does not publish or modify enrollment or Keycloak accounts");
