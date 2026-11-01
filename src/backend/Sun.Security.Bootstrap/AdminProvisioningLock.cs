using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Cross-instance session advisory lock for a single admin provisioning ID.
/// Both key parts are stable across processes; collisions only serialize unrelated IDs.
/// This is a coordination lease, not a fencing token against external Keycloak writers.
/// </summary>
public sealed class AdminProvisioningLock(NpgsqlDataSource dataSource)
{
    // Two-int PostgreSQL advisory locks occupy a separate key space from bigint locks.
    private const int NamespaceKey = 0x4F525956; // ORYV

    public async Task<Lease?> TryAcquireAsync(
        Guid provisioningId, CancellationToken cancellationToken = default)
    {
        if (provisioningId == Guid.Empty)
            throw new ArgumentException("A provisioning ID is required.", nameof(provisioningId));

        // Domain separation ensures the same UUID is not accidentally reused by
        // another advisory-lock feature with a different purpose.
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(
            "oryva:admin-provisioning:" + provisioningId.ToString("N")));
        var key = BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(0, 4));
        var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        try
        {
            await using var command = new NpgsqlCommand(
                "SELECT pg_try_advisory_lock(@namespace_key, @id_key)", connection);
            command.Parameters.AddWithValue("namespace_key", NamespaceKey);
            command.Parameters.AddWithValue("id_key", key);
            var acquired = (bool)(await command.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Admin advisory lock returned no result."));
            if (!acquired)
            {
                await connection.DisposeAsync();
                return null;
            }

            return new Lease(connection, key);
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }

    public sealed class Lease(NpgsqlConnection connection, int key) : IAsyncDisposable
    {
        private int _disposed;

        public async Task EnsureHeldAsync(CancellationToken cancellationToken = default)
        {
            if (Volatile.Read(ref _disposed) != 0)
                throw new InvalidOperationException("Admin provisioning lease is disposed.");

            await using var command = new NpgsqlCommand("""
                SELECT EXISTS (
                    SELECT 1 FROM pg_locks
                    WHERE locktype = 'advisory' AND pid = pg_backend_pid()
                      AND granted AND objsubid = 2
                      AND classid::bigint = @namespace_unsigned
                      AND objid::bigint = @id_unsigned)
                """, connection);
            command.Parameters.AddWithValue("namespace_unsigned", (long)(uint)NamespaceKey);
            command.Parameters.AddWithValue("id_unsigned", (long)(uint)key);
            var held = (bool)(await command.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Admin advisory lease check returned no result."));
            if (!held)
                throw new InvalidOperationException("Admin provisioning advisory lease was lost.");
        }

        public async ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;

            try
            {
                if (connection.State == System.Data.ConnectionState.Open)
                {
                    await using var command = new NpgsqlCommand(
                        "SELECT pg_advisory_unlock(@namespace_key, @id_key)", connection);
                    command.Parameters.AddWithValue("namespace_key", NamespaceKey);
                    command.Parameters.AddWithValue("id_key", key);
                    var released = (bool)(await command.ExecuteScalarAsync()
                        ?? throw new InvalidOperationException("Admin advisory unlock returned no result."));
                    if (!released)
                        throw new InvalidOperationException("Admin provisioning lease was not held on release.");
                }
            }
            catch
            {
                // Never return a session with potentially leaked advisory locks to the pool.
                NpgsqlConnection.ClearPool(connection);
                throw;
            }
            finally
            {
                await connection.DisposeAsync();
            }
        }
    }
}

public sealed class AdminProvisioningBusyException()
    : InvalidOperationException("Admin provisioning recovery is already in progress.");
