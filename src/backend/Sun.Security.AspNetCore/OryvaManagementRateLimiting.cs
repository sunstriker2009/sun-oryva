using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Bounded, per-authenticated-subject management-write throttling.
/// This is an in-process defense-in-depth control, not a distributed quota.
/// Apply after authentication and authorization so untrusted client headers
/// cannot select partitions and rejected identities cannot consume quotas.
/// </summary>
public static class OryvaManagementRateLimiting
{
    public const string PolicyName = "Oryva.ManagementWrite";

    public static IServiceCollection AddOryvaManagementRateLimiting(
        this IServiceCollection services, int permitsPerMinute = 10)
    {
        ArgumentNullException.ThrowIfNull(services);
        if (permitsPerMinute is < 1 or > 120)
            throw new ArgumentOutOfRangeException(nameof(permitsPerMinute),
                "Management write limit must be between 1 and 120 per minute.");

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.AddPolicy(PolicyName, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    GetPartitionKey(context.User),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = permitsPerMinute,
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0,
                        QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                        AutoReplenishment = true
                    }));
            options.OnRejected = async (context, cancellationToken) =>
            {
                context.HttpContext.Response.StatusCode =
                    StatusCodes.Status429TooManyRequests;
                context.HttpContext.Response.Headers.CacheControl = "no-store";
                if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    context.HttpContext.Response.Headers.RetryAfter =
                        Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds))
                            .ToString(CultureInfo.InvariantCulture);
                }
                await context.HttpContext.Response.WriteAsJsonAsync(
                    new { error = "management_rate_limit_exceeded" },
                    cancellationToken);
            };
        });
        return services;
    }

    /// <summary>
    /// Never trust client-controlled IP forwarding headers for quota identity.
    /// Duplicate/missing subject claims share a fail-closed partition; endpoint
    /// authorization separately rejects them.
    /// </summary>
    public static string GetPartitionKey(ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        var subjects = principal.FindAll("sub").Select(claim => claim.Value).ToArray();
        return principal.Identity?.IsAuthenticated == true &&
               subjects.Length == 1 &&
               !string.IsNullOrWhiteSpace(subjects[0])
            ? "subject:" + subjects[0]
            : "invalid-subject";
    }
}
