using Microsoft.AspNetCore.Http;
using Npgsql;
using Sun.Security.AspNetCore;
using Sun.Security.Bootstrap;

// No PostgreSQL connection is opened: malformed or unguarded requests must
// be rejected before any database operation. This is a fail-closed policy test,
// NOT an integration test for successful rotation or revocation.
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

var missing = new DefaultHttpContext();
if (await lifecycle.RotateAsync(missing, Guid.Empty) ||
    await lifecycle.RevokeAsync(missing, Guid.Empty))
    throw new Exception("Missing session cookie was accepted.");

Console.WriteLine("PASS unguarded/missing-cookie lifecycle requests fail closed without DB access");
Console.WriteLine("NOTE PostgreSQL/TestServer success, replay, concurrency and expiry E2E still required");
