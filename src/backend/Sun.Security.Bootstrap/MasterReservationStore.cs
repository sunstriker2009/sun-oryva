using System.Data;
using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// PostgreSQL-owned single-master reservation state.
/// Does not provision or authorize Keycloak identities.
/// </summary>
public sealed class MasterReservationStore(NpgsqlDataSource dataSource)
{
    /// <summary>
    /// Read-only runtime lookup. Never creates or activates a reservation.
    /// Missing or pending state denies master authorization.
    /// </summary>
    public async Task<string?> GetActiveMasterSubjectAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand(
            "SELECT subject_id FROM oryva.master_bootstrap " +
            "WHERE singleton_id = 1 AND state = 'active' AND subject_id IS NOT NULL",
            connection);
        return (string?)await command.ExecuteScalarAsync(cancellationToken);
    }

    public async Task<MasterReservation> ReserveAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await using (var insert = new NpgsqlCommand(
            """
            INSERT INTO oryva.master_bootstrap (singleton_id, state)
            VALUES (1, 'pending')
            ON CONFLICT (singleton_id) DO NOTHING;
            """, connection, transaction))
        {
            await insert.ExecuteNonQueryAsync(cancellationToken);
        }

        MasterReservation reservation;
        await using (var select = new NpgsqlCommand(
            """
            SELECT state, subject_id
            FROM oryva.master_bootstrap
            WHERE singleton_id = 1
            FOR UPDATE;
            """, connection, transaction))
        await using (var reader = await select.ExecuteReaderAsync(cancellationToken))
        {
            if (!await reader.ReadAsync(cancellationToken))
                throw new InvalidOperationException("Master reservation row is missing.");

            reservation = new MasterReservation(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetString(1));
        }

        await transaction.CommitAsync(cancellationToken);
        return reservation;
    }

    /// <summary>
    /// Marks a previously verified Keycloak subject as active.
    /// Caller MUST verify identity, role assignment and uniqueness against Keycloak first.
    /// </summary>
    public async Task<MasterReservation> ActivateVerifiedAsync(
        string verifiedSubjectId,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(verifiedSubjectId);

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        await using var command = new NpgsqlCommand(
            """
            UPDATE oryva.master_bootstrap
            SET state = 'active',
                subject_id = @subject,
                activated_at = now()
            WHERE singleton_id = 1
              AND state = 'pending'
              AND subject_id IS NULL
            RETURNING subject_id;
            """, connection, transaction);
        command.Parameters.AddWithValue("subject", verifiedSubjectId);
        var updated = (string?)await command.ExecuteScalarAsync(cancellationToken);
        if (updated is null)
        {
            await using var existing = new NpgsqlCommand(
                """
                SELECT subject_id FROM oryva.master_bootstrap
                WHERE singleton_id = 1 AND state = 'active'
                FOR UPDATE;
                """, connection, transaction);
            var active = (string?)await existing.ExecuteScalarAsync(cancellationToken);
            if (!string.Equals(active, verifiedSubjectId, StringComparison.Ordinal))
                throw new InvalidOperationException("Master already assigned to a different subject or reservation missing.");
        }
        await transaction.CommitAsync(cancellationToken);
        return new MasterReservation("active", verifiedSubjectId);
    }
}

public sealed record MasterReservation(string State, string? SubjectId)
{
    public bool IsActive => State == "active";
}
