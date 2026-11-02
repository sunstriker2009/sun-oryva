using System.Data;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;

namespace Sun.Security.AspNetCore;

/// <summary>
/// Opt-in cross-replica admission counter for future browser ceremony routes.
/// Uses the database clock and serializes global then IP rows in one transaction.
/// This is not authentication, email proof or an account-activation gate.
/// </summary>
public sealed class OryvaBrowserAdmissionQuota
{
    private readonly NpgsqlDataSource _database;
    private readonly byte[] _ipHmacKey;

    public OryvaBrowserAdmissionQuota(NpgsqlDataSource database, byte[] ipHmacKey)
    {
        _database = database ?? throw new ArgumentNullException(nameof(database));
        ArgumentNullException.ThrowIfNull(ipHmacKey);
        if (ipHmacKey.Length < 32 || ipHmacKey.All(b => b == 0))
            throw new ArgumentException("A secret HMAC key of at least 32 bytes is required.", nameof(ipHmacKey));
        _ipHmacKey = (byte[])ipHmacKey.Clone();
    }

    /// <summary>
    /// Both counters are charged, even when a request is denied. Failed
    /// database transactions grant no admission. Limits may be 1..1000.
    /// </summary>
    public async Task<bool> TryConsumeAsync(
        IPAddress clientIp, int perIpPerMinute, int globalPerMinute,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(clientIp);
        ValidateLimit(perIpPerMinute, nameof(perIpPerMinute));
        ValidateLimit(globalPerMinute, nameof(globalPerMinute));

        var address = clientIp.IsIPv4MappedToIPv6 ? clientIp.MapToIPv4() : clientIp;
        if (IPAddress.Any.Equals(address) || IPAddress.IPv6Any.Equals(address) ||
            IPAddress.None.Equals(address) || IPAddress.IPv6None.Equals(address) ||
            (address.AddressFamily != AddressFamily.InterNetwork &&
             address.AddressFamily != AddressFamily.InterNetworkV6))
            throw new ArgumentException("A concrete client IP is required.", nameof(clientIp));

        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            Array.Clear(bytes, 8, 8); // Aggregate rotating IPv6 interface IDs by /64.
        var partition = new byte[bytes.Length + 1];
        partition[0] = address.AddressFamily == AddressFamily.InterNetwork ? (byte)4 : (byte)6;
        Buffer.BlockCopy(bytes, 0, partition, 1, bytes.Length);
        var ipKey = Convert.ToHexString(HMACSHA256.HashData(_ipHmacKey, partition));

        await using var connection = await _database.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.ReadCommitted, cancellationToken);
        DateTime bucket;
        await using (var clock = new NpgsqlCommand(
            "SELECT date_trunc('minute', clock_timestamp());", connection, transaction))
        {
            bucket = (DateTime)(await clock.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("PostgreSQL clock unavailable."));
        }

        // Consistent lock ordering prevents global/IP deadlocks across replicas.
        var globalAllowed = await ChargeAsync(
            connection, transaction, "global", "global", bucket, globalPerMinute, cancellationToken);
        var ipAllowed = await ChargeAsync(
            connection, transaction, "ip", ipKey, bucket, perIpPerMinute, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return globalAllowed && ipAllowed;
    }

    private static void ValidateLimit(int limit, string name)
    {
        if (limit is < 1 or > 1000)
            throw new ArgumentOutOfRangeException(name, "Quota must be between 1 and 1000.");
    }

    private static async Task<bool> ChargeAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        string scope, string key, DateTime bucket, int limit,
        CancellationToken cancellationToken)
    {
        await using var command = new NpgsqlCommand("""
            INSERT INTO oryva.browser_admission_quotas
                (scope, partition_key, window_start, request_count, updated_at)
            VALUES (@scope, @key, @bucket, 1, clock_timestamp())
            ON CONFLICT (scope, partition_key) DO UPDATE SET
                window_start = CASE
                    WHEN oryva.browser_admission_quotas.window_start < EXCLUDED.window_start
                    THEN EXCLUDED.window_start
                    ELSE oryva.browser_admission_quotas.window_start END,
                request_count = CASE
                    WHEN oryva.browser_admission_quotas.window_start < EXCLUDED.window_start
                    THEN 1
                    WHEN oryva.browser_admission_quotas.request_count < @limit
                    THEN oryva.browser_admission_quotas.request_count + 1
                    ELSE GREATEST(oryva.browser_admission_quotas.request_count, @limit + 1)
                    END,
                updated_at = clock_timestamp()
            RETURNING request_count <= @limit;
            """, connection, transaction);
        command.Parameters.AddWithValue("scope", scope);
        command.Parameters.AddWithValue("key", key);
        command.Parameters.AddWithValue("bucket", bucket);
        command.Parameters.AddWithValue("limit", limit);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Quota update returned no result."));
    }
}

/// <summary>
/// Middleware is intentionally not registered by the ORYVA API. Apply only
/// after routing and explicitly reviewed trusted-proxy middleware. The sole
/// IP source is Connection.RemoteIpAddress; raw forwarding headers are ignored.
/// </summary>
public static class OryvaBrowserAdmissionQuotaExtensions
{
    public static IServiceCollection AddOryvaBrowserAdmissionQuota(
        this IServiceCollection services, byte[] ipHmacKey)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(ipHmacKey);
        if (ipHmacKey.Length < 32 || ipHmacKey.All(b => b == 0))
            throw new ArgumentException("A secret HMAC key of at least 32 bytes is required.", nameof(ipHmacKey));
        var secretCopy = (byte[])ipHmacKey.Clone();
        return services.AddSingleton(provider => new OryvaBrowserAdmissionQuota(
            provider.GetRequiredService<NpgsqlDataSource>(), secretCopy));
    }

    public static IApplicationBuilder UseOryvaBrowserAdmissionQuota(
        this IApplicationBuilder app, int perIpPerMinute, int globalPerMinute)
    {
        ArgumentNullException.ThrowIfNull(app);
        if (perIpPerMinute is < 1 or > 1000 || globalPerMinute is < 1 or > 1000)
            throw new ArgumentOutOfRangeException(nameof(perIpPerMinute),
                "Browser quota limits must be 1..1000.");

        return app.Use(async (context, next) =>
        {
            if (context.GetEndpoint()?.Metadata.GetMetadata<OryvaBrowserCeremonyAttribute>() is null)
            {
                await next();
                return;
            }

            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";

            if (context.Connection.RemoteIpAddress is null)
            {
                await RejectAsync(context, StatusCodes.Status503ServiceUnavailable);
                return;
            }

            bool admitted;
            try
            {
                admitted = await context.RequestServices
                    .GetRequiredService<OryvaBrowserAdmissionQuota>()
                    .TryConsumeAsync(context.Connection.RemoteIpAddress,
                        perIpPerMinute, globalPerMinute, context.RequestAborted);
            }
            catch (Exception error) when (error is NpgsqlException or TimeoutException
                or InvalidOperationException or ArgumentException)
            {
                await RejectAsync(context, StatusCodes.Status503ServiceUnavailable);
                return;
            }

            if (!admitted)
            {
                context.Response.Headers.RetryAfter = "60";
                await RejectAsync(context, StatusCodes.Status429TooManyRequests);
                return;
            }
            await next();
        });
    }

    private static async Task RejectAsync(HttpContext context, int status)
    {
        context.Response.StatusCode = status;
        await context.Response.WriteAsJsonAsync(
            new { error = "browser_admission_rejected" }, context.RequestAborted);
    }
}
