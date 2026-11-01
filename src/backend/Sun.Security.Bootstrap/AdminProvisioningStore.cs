using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Reserves admin account ownership in PostgreSQL before contacting Keycloak.
/// This store does not grant roles or activate identities.
/// </summary>
public sealed class AdminProvisioningStore(NpgsqlDataSource dataSource)
{
    public async Task<AdminProvisioningReservation> ReserveAsync(
        string username, string email, string actorSubject,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        var id = Guid.NewGuid();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO oryva.admin_provisioning
                (id, username, email, requested_by_subject)
            VALUES (@id, @username, @email, @actor)
            ON CONFLICT DO NOTHING
            RETURNING id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("username", username);
        command.Parameters.AddWithValue("email", email);
        command.Parameters.AddWithValue("actor", actorSubject);
        var inserted = await command.ExecuteScalarAsync(cancellationToken);
        if (inserted is null)
            throw new InvalidOperationException(
                "Admin provisioning identity already reserved; reconciliation required.");
        return new AdminProvisioningReservation(id, username, email, actorSubject);
    }

    public async Task MarkReconciliationRequiredAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            UPDATE oryva.admin_provisioning
            SET state = 'reconciliation_required', updated_at = now()
            WHERE id = @id AND state = 'reserved';
            """, connection);
        command.Parameters.AddWithValue("id", id);
        if (await command.ExecuteNonQueryAsync(cancellationToken) != 1)
            throw new InvalidOperationException("Admin provisioning reservation is not pending.");
    }
}

public sealed record AdminProvisioningReservation(
    Guid Id, string Username, string Email, string RequestedBySubject);
