using Microsoft.AspNetCore.Http;
using Sun.Security.Bootstrap;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Unregistered, opt-in orchestration of guarded browser-session lifecycle operations.
/// This is not authentication, email ownership verification, credential enrollment,
/// or authorization to enable a Keycloak identity. No HTTP routes are registered.
/// </summary>
public sealed class OryvaGuardedBrowserSessionLifecycle(
    ViewerInvitationBrowserExchangeStore sessions)
{
    /// <summary>
    /// Rotates the PostgreSQL bearer atomically before issuing the replacement
    /// cookie. The original database expiration is preserved by the store.
    /// Returns false for any rejected request or stale/invalid bearer.
    /// </summary>
    public async Task<bool> RotateAsync(
        HttpContext context, Guid viewerId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Response.HasStarted ||
            !OryvaBrowserSessionCookie.TryReadUntrustedBearer(context, out var bearer))
            return false;

        // A viewer ID is only a database lookup key. The matching digest and
        // viewer/challenge/subject state are checked transactionally by the store.
        var rotated = await sessions.RotateAsync(
            viewerId, bearer, cancellationToken);
        if (rotated is null)
            return false;

        // Database rotation has committed. If headers cannot be issued, the old
        // bearer is already invalid; never return the new bearer in a response body.
        return OryvaBrowserSessionCookie.TryIssue(
            context, rotated.BrowserSecret, new DateTimeOffset(rotated.ExpiresAtUtc, TimeSpan.Zero));
    }

    /// <summary>
    /// Revokes the database bearer before expiring the browser cookies.
    /// A cookie deletion alone is never considered successful revocation.
    /// </summary>
    public async Task<bool> RevokeAsync(
        HttpContext context, Guid viewerId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (context.Response.HasStarted ||
            !OryvaBrowserSessionCookie.TryReadUntrustedBearer(context, out var bearer))
            return false;

        if (!await sessions.RevokeAsync(viewerId, bearer, cancellationToken))
            return false;

        return OryvaBrowserSessionCookie.TryClear(context);
    }
}
