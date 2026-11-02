using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Explicit, opt-in CSRF bootstrap for a future same-origin browser ceremony.
/// The returned token is not an identity, invitation, browser session, or
/// credential-enrollment authorization. No production route is registered.
/// </summary>
public static class OryvaBrowserCsrfBootstrap
{
    public const string BootstrapHeaderName = "X-Oryva-Csrf-Bootstrap";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Build a GET handler with its canonical HTTPS origin validated at setup.
    /// Browser JavaScript must request it with X-Oryva-Csrf-Bootstrap: 1,
    /// retain csrfToken only in memory, and send it as X-Oryva-Csrf on POST.
    /// The cookie is HttpOnly and never exposed to browser JavaScript.
    /// </summary>
    public static RequestDelegate CreateHandler(string expectedOrigin)
    {
        var expected = OryvaBrowserRequestGuard.ValidateOrigin(expectedOrigin);
        return async context =>
        {
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["Pragma"] = "no-cache";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            context.Response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
            context.Response.Headers["Content-Security-Policy"] =
                "default-src 'none'; frame-ancestors 'none'";

            var request = context.Request;
            var valid = HttpMethods.IsGet(request.Method) &&
                request.IsHttps &&
                !request.QueryString.HasValue &&
                string.Equals(request.Host.Host, expected.Host,
                    StringComparison.OrdinalIgnoreCase) &&
                request.Host.Port == (expected.IsDefaultPort ? null : expected.Port) &&
                request.Headers.TryGetValue(BootstrapHeaderName, out var bootstrap) &&
                bootstrap.Count == 1 && bootstrap[0] == "1" &&
                (!request.Headers.TryGetValue("Origin", out var origins) ||
                    (origins.Count == 1 &&
                     string.Equals(origins[0], expected.GetLeftPart(UriPartial.Authority),
                         StringComparison.Ordinal))) &&
                (!request.Headers.TryGetValue("Sec-Fetch-Site", out var sites) ||
                    (sites.Count == 1 && sites[0] == "same-origin"));

            if (!valid)
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(
                    new { error = "browser_request_rejected" },
                    context.RequestAborted);
                return;
            }

            var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            context.Response.Cookies.Append(
                OryvaBrowserRequestGuard.CsrfCookieName, token,
                new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Path = "/",
                    MaxAge = Lifetime,
                    IsEssential = true
                    // Never set Domain: __Host- cookies must be host-only.
                });
            await context.Response.WriteAsJsonAsync(
                new { csrfToken = token }, context.RequestAborted);
        };
    }
}
