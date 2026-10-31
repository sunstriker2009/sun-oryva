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

            return new Lease(connection, LockKey);
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
    public sealed class Lease(NpgsqlConnection connection, long lockKey) : IAsyncDisposable
    {
        private int _disposed;

        /// <summary>
        /// Confirms this PostgreSQL session still holds the advisory lock.
        /// Best-effort continuity check, not a fencing token.
        /// </summary>
        public async Task EnsureHeldAsync(CancellationToken cancellationToken = default)
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new InvalidOperationException("Provisioning lease is disposed.");

            await using var command = new NpgsqlCommand(
                "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' " +
                "AND pid = pg_backend_pid() AND granted AND classid::bigint = @high " +
                "AND objid::bigint = @low AND objsubid = 1)", connection);
            command.Parameters.AddWithValue("high", (long)(uint)(lockKey >> 32));
            command.Parameters.AddWithValue("low", (long)(uint)lockKey);
            var held = (bool)(await command.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Provisioning lease check returned no result."));
            if (!held)
                throw new InvalidOperationException("Provisioning advisory lock was lost.");
        }


        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            // Session-level advisory locks survive ordinary transaction completion.
            // Explicitly release the lock before returning a connection to the pool.
            // A broken connection is discarded; never swallow an unlock failure.
            try
            {
                if (connection.State == System.Data.ConnectionState.Open)
                {
                    await using var command = new NpgsqlCommand(
                        "SELECT pg_advisory_unlock(@lock_key)", connection);
                    command.Parameters.AddWithValue("lock_key", lockKey);
                    var released = (bool)(await command.ExecuteScalarAsync()
                        ?? throw new InvalidOperationException("Advisory unlock returned no result."));
                    if (!released)
                        throw new InvalidOperationException("Provisioning lease was not held during release.");
                }
            }
            finally
            {
                NpgsqlConnection.ClearPool(connection);
                await connection.DisposeAsync();
            }
        }
    }
}
