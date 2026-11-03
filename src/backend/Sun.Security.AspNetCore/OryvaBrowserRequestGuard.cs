using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Opt-in marker for future invitation browser mutation endpoints. Applying
/// the marker never publishes an endpoint or grants enrollment permission.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class OryvaBrowserCeremonyAttribute : Attribute { }

/// <summary>
/// Defense-in-depth HTTP request boundary for future browser invitation POSTs.
/// It is not an invitation, session, email-verification or credential grant.
/// The caller must separately enforce distributed IP quotas, one-time
/// enrollment and Keycloak ownership/activation invariants.
/// </summary>
public static class OryvaBrowserRequestGuard
{
    public const string CsrfCookieName = "__Host-oryva-csrf";
    public const string CsrfHeaderName = "X-Oryva-Csrf";
    private static readonly object ValidatedPostKey = new();

    // An opaque per-request marker, set only after every guard check passes.
    // Cookie helpers must not run on unmarked or rejected endpoints.
    internal static bool HasValidatedBrowserPost(HttpContext context) =>
        context.Items.ContainsKey(ValidatedPostKey);

    public static IApplicationBuilder UseOryvaBrowserRequestGuard(
        this IApplicationBuilder app, string expectedOrigin)
    {
        ArgumentNullException.ThrowIfNull(app);
        var origin = ValidateOrigin(expectedOrigin);
        return app.Use(async (context, next) =>
        {
            if (context.GetEndpoint()?.Metadata
                    .GetMetadata<OryvaBrowserCeremonyAttribute>() is null)
            {
                await next();
                return;
            }

            // Always suppress browser caches and referrer leakage, including
            // on a denied request. No token, cookie or origin is logged.
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";

            if (!IsAllowed(context.Request, origin))
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                await context.Response.WriteAsJsonAsync(
                    new { error = "browser_request_rejected" },
                    context.RequestAborted);
                return;
            }
            context.Items[ValidatedPostKey] = true;
            await next();
        });
    }

    internal static Uri ValidateOrigin(string value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps ||
            !string.IsNullOrEmpty(uri.UserInfo) ||
            uri.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(uri.Query) ||
            !string.IsNullOrEmpty(uri.Fragment) ||
            uri.Host.EndsWith(".", StringComparison.Ordinal) ||
            !string.Equals(value.TrimEnd('/'),
                uri.GetLeftPart(UriPartial.Authority),
                StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException(
                "A single canonical HTTPS origin without path, credentials or query is required.",
                nameof(value));
        return uri;
    }

    private static bool IsAllowed(HttpRequest request, Uri expected)
    {
        // No forwarding headers are trusted here. A reverse proxy must be
        // explicitly configured with known proxies BEFORE this middleware.
        if (!HttpMethods.IsPost(request.Method) || !request.IsHttps ||
            !string.Equals(request.Host.Host, expected.Host,
                StringComparison.OrdinalIgnoreCase) ||
            request.Host.Port != (expected.IsDefaultPort ? null : expected.Port))
            return false;

        if (!request.Headers.TryGetValue("Origin", out var origins) ||
            origins.Count != 1 ||
            !string.Equals(origins[0],
                expected.GetLeftPart(UriPartial.Authority),
                StringComparison.Ordinal))
            return false;

        // An absent Fetch Metadata header is allowed for older browsers,
        // but any supplied cross-site/same-site/none value is rejected.
        if (request.Headers.TryGetValue("Sec-Fetch-Site", out var sites) &&
            (sites.Count != 1 || sites[0] != "same-origin"))
            return false;

        if (!request.Headers.TryGetValue(CsrfHeaderName, out var headers) ||
            headers.Count != 1 || !IsTokenShape(headers[0]))
            return false;

        // Reject ambiguous duplicate cookies rather than trusting the first
        // or last parser-selected value. The __Host- prefix requires a Secure,
        // Path=/, host-only cookie at issuance.
        if (!request.Headers.TryGetValue("Cookie", out var rawCookies) ||
            rawCookies.Count != 1 ||
            rawCookies[0]!.Split(';', StringSplitOptions.TrimEntries)
                .Count(part => part.StartsWith(CsrfCookieName + "=",
                    StringComparison.Ordinal)) != 1 ||
            !request.Cookies.TryGetValue(CsrfCookieName, out var cookie) ||
            !IsTokenShape(cookie))
            return false;

        return CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(headers[0]!),
            Encoding.ASCII.GetBytes(cookie));
    }

    private static bool IsTokenShape(string? value) =>
        value is { Length: 43 } &&
        value.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z'
            or >= '0' and <= '9' or '-' or '_');
}
