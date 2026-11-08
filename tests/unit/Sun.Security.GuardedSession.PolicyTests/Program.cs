using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Npgsql;
using Sun.Security.AspNetCore;
using Sun.Security.Bootstrap;

// The connection intentionally points at a closed port. Every request below
// MUST fail before opening PostgreSQL. This tests the guarded HTTP boundary,
// not the successful database lifecycle or Keycloak enrollment.
await using var source = NpgsqlDataSource.Create(
    "Host=127.0.0.1;Port=1;Database=oryva_not_connected;Username=oryva_test;Timeout=1");
var lifecycle = new OryvaGuardedBrowserSessionLifecycle(
    new ViewerInvitationBrowserExchangeStore(source));

var unguarded = new DefaultHttpContext();
unguarded.Request.Method = HttpMethods.Post;
unguarded.Request.Scheme = "https";
unguarded.Request.Host = new HostString("enroll.oryva.example");
unguarded.Request.Headers.Cookie =
    OryvaBrowserSessionCookie.Name + "=" + new string('A', 43);
if (await lifecycle.RotateAsync(unguarded, Guid.NewGuid()) ||
    await lifecycle.RevokeAsync(unguarded, Guid.NewGuid()) ||
    unguarded.Response.Headers.ContainsKey("Set-Cookie"))
    throw new Exception("Unguarded request reached session mutation or changed cookies.");

// Once response headers have started, a valid-looking bearer must not
// trigger a database mutation or attempt to issue/clear cookies.
foreach (var operation in new[] { "rotate", "revoke" })
{
    var started = new DefaultHttpContext();
    started.Request.Method = HttpMethods.Post;
    started.Request.Scheme = "https";
    started.Request.Host = new HostString("enroll.oryva.example");
    started.Request.Headers.Cookie =
        OryvaBrowserSessionCookie.Name + "=" + new string('A', 43);
    started.Response.Body = new MemoryStream();
    await started.Response.StartAsync();
    if (!started.Response.HasStarted)
        throw new Exception("Test setup failed: response has not started.");
    var allowed = operation == "rotate"
        ? await lifecycle.RotateAsync(started, Guid.NewGuid())
        : await lifecycle.RevokeAsync(started, Guid.NewGuid());
    if (allowed || started.Response.Headers.ContainsKey("Set-Cookie"))
        throw new Exception("Started response must fail closed: " + operation);
}

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    EnvironmentName = "Development"
});
builder.WebHost.UseTestServer();
await using var app = builder.Build();
app.UseRouting();
app.UseOryvaBrowserRequestGuard("https://enroll.oryva.example");
var handlerCalls = 0;
app.MapPost("/rotate", async (HttpContext ctx) =>
{
    handlerCalls++;
    return await lifecycle.RotateAsync(ctx, Guid.NewGuid())
        ? Results.NoContent() : Results.StatusCode(403);
}).WithMetadata(new OryvaBrowserCeremonyAttribute());
app.MapPost("/revoke", async (HttpContext ctx) =>
{
    handlerCalls++;
    return await lifecycle.RevokeAsync(ctx, Guid.NewGuid())
        ? Results.NoContent() : Results.StatusCode(403);
}).WithMetadata(new OryvaBrowserCeremonyAttribute());
await app.StartAsync();
using var client = app.GetTestClient();
var csrf = new string('A', 43);
var csrfCookie = OryvaBrowserRequestGuard.CsrfCookieName + "=" + csrf;
var sessionName = OryvaBrowserSessionCookie.Name + "=";

async Task DeniedAsync(string route, string? origin, string cookies,
    string? csrfHeader = null, int expectedHandlerDelta = 0)
{
    var before = handlerCalls;
    using var request = new HttpRequestMessage(HttpMethod.Post,
        "https://enroll.oryva.example" + route);
    request.Headers.Host = "enroll.oryva.example";
    if (origin is not null)
        request.Headers.TryAddWithoutValidation("Origin", origin);
    request.Headers.TryAddWithoutValidation("Sec-Fetch-Site", "same-origin");
    if (csrfHeader is not null)
        request.Headers.TryAddWithoutValidation(
            OryvaBrowserRequestGuard.CsrfHeaderName, csrfHeader);
    request.Headers.TryAddWithoutValidation("Cookie", cookies);
    using var response = await client.SendAsync(request);
    if (response.StatusCode != HttpStatusCode.Forbidden ||
        response.Headers.Contains("Set-Cookie") ||
        response.Headers.CacheControl?.NoStore != true ||
        handlerCalls - before != expectedHandlerDelta)
        throw new Exception("Unsafe browser lifecycle denial: " + route);
}
foreach (var route in new[] { "/rotate", "/revoke" })
{
    // Rejected by origin/CSRF guard, without entering the handler.
    await DeniedAsync(route, "https://attacker.example",
        csrfCookie + "; " + sessionName + new string('B', 43),
        csrf, 0);
    await DeniedAsync(route, "https://enroll.oryva.example",
        csrfCookie + "; " + sessionName + new string('B', 43),
        null, 0);

    // Valid CSRF, but missing/malformed/duplicate bearer is denied by
    // the cookie transport before the database connection can be opened.
    await DeniedAsync(route, "https://enroll.oryva.example",
        csrfCookie, csrf, 1);
    await DeniedAsync(route, "https://enroll.oryva.example",
        csrfCookie + "; " + sessionName + "short", csrf, 1);
    var session = sessionName + new string('B', 43);
    await DeniedAsync(route, "https://enroll.oryva.example",
        csrfCookie + "; " + session + "; " + session, csrf, 1);
}
await app.StopAsync();
Console.WriteLine("PASS guarded TestServer origin/CSRF, missing/malformed/duplicate bearer denials");
Console.WriteLine("PASS rejected lifecycle calls cannot reach PostgreSQL or mutate cookies");
Console.WriteLine("NOTE successful PostgreSQL rotation/revocation, replay and concurrency E2E remain outstanding");
