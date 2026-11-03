using Microsoft.AspNetCore.Http;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Opt-in cookie transport for a previously committed, database-validated
/// invitation browser bearer. This is NOT a login, authentication decision,
/// email ownership proof, or permission to mutate Keycloak credentials.
/// Only guarded same-origin POST handlers may use this helper.
/// </summary>
public static class OryvaBrowserSessionCookie
{
    public const string Name = "__Host-oryva-browser";
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Issue or replace a browser cookie ONLY AFTER the caller has committed
    /// a valid exchange/rotation in PostgreSQL. The original database expiry
    /// is mandatory and must never be extended by a cookie replacement.
    /// </summary>
    public static bool TryIssue(
        HttpContext context, string bearer, DateTimeOffset databaseExpiresAt)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!OryvaBrowserRequestGuard.HasValidatedBrowserPost(context) ||
            context.Response.HasStarted || !IsBearerShape(bearer))
            return false;

        var remaining = databaseExpiresAt - DateTimeOffset.UtcNow;
        // Round down, never up: a cookie must not outlive the database bearer.
        var seconds = Math.Floor(remaining.TotalSeconds);
        if (seconds < 1 || seconds > MaximumLifetime.TotalSeconds)
            return false;

        ApplyNonDisclosureHeaders(context.Response);
        context.Response.Cookies.Append(Name, bearer, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            MaxAge = TimeSpan.FromSeconds(seconds),
            Expires = databaseExpiresAt,
            IsEssential = true
            // No Domain: __Host- requires a host-only, root-path cookie.
        });
        return true;
    }

    /// <summary>
    /// Extract an UNTRUSTED opaque bearer from exactly one host-only cookie.
    /// The caller MUST verify its digest and all viewer/Keycloak state against
    /// PostgreSQL under the required locks; shape is not authentication.
    /// </summary>
    public static bool TryReadUntrustedBearer(
        HttpContext context, out string bearer)
    {
        ArgumentNullException.ThrowIfNull(context);
        bearer = string.Empty;
        if (!OryvaBrowserRequestGuard.HasValidatedBrowserPost(context) ||
            !context.Request.Headers.TryGetValue("Cookie", out var raw) ||
            raw.Count != 1 ||
            raw[0]!.Split(';', StringSplitOptions.TrimEntries)
                .Count(part => part.StartsWith(Name + "=", StringComparison.Ordinal)) != 1 ||
            !context.Request.Cookies.TryGetValue(Name, out var value) ||
            !IsBearerShape(value))
            return false;

        bearer = value;
        return true;
    }

    /// <summary>
    /// Clear the browser and CSRF cookies after a committed revocation or a
    /// terminal enrollment outcome. Clearing a cookie does not revoke the
    /// server-side bearer: the caller must perform that operation separately.
    /// </summary>
    public static bool TryClear(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!OryvaBrowserRequestGuard.HasValidatedBrowserPost(context) ||
            context.Response.HasStarted)
            return false;

        ApplyNonDisclosureHeaders(context.Response);
        foreach (var name in new[] { Name, OryvaBrowserRequestGuard.CsrfCookieName })
            context.Response.Cookies.Delete(name, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = "/",
                IsEssential = true
            });
        return true;
    }

    private static bool IsBearerShape(string? bearer) =>
        bearer is { Length: 43 } &&
        bearer.All(c => c is >= 'A' and <= 'Z' or >= 'a' and <= 'z'
            or >= '0' and <= '9' or '-' or '_');

    private static void ApplyNonDisclosureHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store";
        response.Headers["Pragma"] = "no-cache";
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers["X-Content-Type-Options"] = "nosniff";
        response.Headers["Cross-Origin-Resource-Policy"] = "same-origin";
    }
}
