using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Session-scoped PostgreSQL advisory lock serializing ORYVA master provisioning
/// across instances sharing one deployment database.
/// </summary>
public sealed class MasterProvisioningLock(NpgsqlDataSource dataSource)
{
    // Stable application-specific advisory-lock key; never derive from user input.
    private const long LockKey = 0x4F525956414D5354L;

    /// <summary>Returns null if another coordinator currently owns the lock.</summary>
    public async Task<Lease?> TryAcquireAsync(CancellationToken cancellationToken = default)
    {
        var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        try
        {
            await using var command = new NpgsqlCommand(
                "SELECT pg_try_advisory_lock(@lock_key)", connection);
            command.Parameters.AddWithValue("lock_key", LockKey);
            var acquired = (bool)(await command.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Advisory lock returned no result."));
            if (!acquired)
            {
                await connection.DisposeAsync();
                return null;
            }

            return new Lease(connection);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    /// <summary>
    /// The lease owns its database connection. Keep it alive throughout Keycloak
    /// operations. Never share the underlying connection with other callers.
    /// </summary>
    public sealed class Lease(NpgsqlConnection connection) : IAsyncDisposable
    {
        private int _disposed;

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            // Closing the session releases PostgreSQL session advisory locks.
            // Clear the pool to avoid a leased lock surviving on a pooled session.
            NpgsqlConnection.ClearPool(connection);
            await connection.DisposeAsync();
        }
    }
}
