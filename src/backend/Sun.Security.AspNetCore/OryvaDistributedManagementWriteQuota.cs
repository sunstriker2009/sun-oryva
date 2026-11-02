using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Sun.Security.AspNetCore;

/// <summary>
/// PostgreSQL is the single source of truth for management write quotas across
/// API replicas. The atomic UPSERT serializes concurrent requests per subject.
/// The database clock, not each application's clock, defines minute boundaries.
/// </summary>
public sealed class OryvaDistributedManagementWriteQuota(NpgsqlDataSource database)
{
    public async Task<bool> TryConsumeAsync(
        string authenticatedPartition, int permitsPerMinute,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authenticatedPartition);
        if (permitsPerMinute is < 1 or > 120)
            throw new ArgumentOutOfRangeException(nameof(permitsPerMinute));

        // Never persist a raw JWT subject; the hash is a stable opaque key
        // shared by all replicas of this ORYVA deployment.
        var subjectKey = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(authenticatedPartition)));
        await using var connection = await database.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            WITH tick AS (
                SELECT date_trunc('minute', clock_timestamp()) AS bucket
            )
            INSERT INTO oryva.management_write_quotas
                (subject_key, window_start, request_count, updated_at)
            SELECT @subject_key, bucket, 1, clock_timestamp() FROM tick
            ON CONFLICT (subject_key) DO UPDATE
                SET window_start = EXCLUDED.window_start,
                    request_count = CASE
                        WHEN oryva.management_write_quotas.window_start < EXCLUDED.window_start
                        THEN 1
                        ELSE oryva.management_write_quotas.request_count + 1
                    END,
                    updated_at = clock_timestamp()
                WHERE oryva.management_write_quotas.window_start < EXCLUDED.window_start
                   OR (oryva.management_write_quotas.window_start = EXCLUDED.window_start
                       AND oryva.management_write_quotas.request_count < @limit)
            RETURNING 1;
            """, connection);
        command.Parameters.AddWithValue("subject_key", subjectKey);
        command.Parameters.AddWithValue("limit", permitsPerMinute);
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }
}

/// <summary>
/// Runs only for endpoints explicitly annotated with the ORYVA management
/// rate-limit policy. Install after routing, authentication and authorization,
/// and before endpoint execution. Database failures reject writes (503).
/// </summary>
public static class OryvaDistributedManagementWriteQuotaExtensions
{
    public static IServiceCollection AddOryvaDistributedManagementWriteQuota(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);
        return services.AddScoped<OryvaDistributedManagementWriteQuota>();
    }

    public static IApplicationBuilder UseOryvaDistributedManagementWriteQuota(
        this IApplicationBuilder app, int permitsPerMinute)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (permitsPerMinute is < 1 or > 120)
            throw new ArgumentOutOfRangeException(nameof(permitsPerMinute));

        return app.Use(async (context, next) =>
        {
            var policy = context.GetEndpoint()?.Metadata
                .GetMetadata<EnableRateLimitingAttribute>();
            if (policy?.PolicyName != OryvaManagementRateLimiting.PolicyName)
            {
                await next(context);
                return;
            }

            // The authorization middleware has already rejected anonymous
            // callers. Never use forwarded headers as a quota partition.
            if (context.User.Identity?.IsAuthenticated != true)
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }

            bool allowed;
            try
            {
                var quota = context.RequestServices
                    .GetRequiredService<OryvaDistributedManagementWriteQuota>();
                allowed = await quota.TryConsumeAsync(
                    OryvaManagementRateLimiting.GetPartitionKey(context.User),
                    permitsPerMinute, context.RequestAborted);
            }
            catch (Exception error) when (error is NpgsqlException or TimeoutException)
            {
                // A missing migration, database outage or transient DB failure
                // must never silently disable the cross-replica quota.
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                context.Response.Headers.CacheControl = "no-store";
                await context.Response.WriteAsJsonAsync(
                    new { error = "management_quota_unavailable" },
                    context.RequestAborted);
                return;
            }

            if (!allowed)
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                context.Response.Headers.CacheControl = "no-store";
                // The database uses fixed calendar-minute windows; 60 seconds
                // is a conservative upper bound, not a precise reset time.
                context.Response.Headers.RetryAfter = "60";
                await context.Response.WriteAsJsonAsync(
                    new { error = "management_rate_limit_exceeded" },
                    context.RequestAborted);
                return;
            }
            await next(context);
        });
    }
}
