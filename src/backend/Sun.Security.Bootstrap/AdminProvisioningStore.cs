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
            WITH reserved AS (
                INSERT INTO oryva.admin_provisioning
                    (id, username, email, requested_by_subject)
                VALUES (@id, @username, @email, @actor)
                ON CONFLICT DO NOTHING
                RETURNING id, requested_by_subject
            )
            INSERT INTO oryva.admin_provisioning_audit
                (provisioning_id, event_type, actor_subject)
            SELECT id, 'reserved', requested_by_subject FROM reserved
            RETURNING provisioning_id;
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

    /// <summary>
    /// Reads a reservation by opaque identifier. Caller must enforce active-master
    /// authorization; this read alone never permits account activation.
    /// </summary>
    public async Task<AdminProvisioningState?> GetAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT id, username, email, requested_by_subject,
                   keycloak_subject_id, state
            FROM oryva.admin_provisioning WHERE id = @id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new AdminProvisioningState(
            reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
            reader.GetString(3), reader.IsDBNull(4) ? null : reader.GetString(4),
            reader.GetString(5));
    }

    /// <summary>
    /// Returns immutable provisioning transition events in commit order.
    /// The API must authorize the caller as the active master before exposing them.
    /// </summary>
    public async Task<IReadOnlyList<AdminProvisioningAuditEvent>> GetAuditAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT event_id, event_type, actor_subject, occurred_at
            FROM oryva.admin_provisioning_audit
            WHERE provisioning_id = @id ORDER BY event_id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var events = new List<AdminProvisioningAuditEvent>();
        while (await reader.ReadAsync(cancellationToken))
            events.Add(new AdminProvisioningAuditEvent(
                reader.GetInt64(0), reader.GetString(1),
                reader.GetString(2), reader.GetFieldValue<DateTime>(3)));
        return events;
    }

    /// <summary>
    /// Binds the verified Keycloak subject to the original reservation.
    /// Does not mark the account prepared until ownership markers are supported.
    /// </summary>
    public async Task BindVerifiedSubjectAsync(
        Guid id, string username, string email, string actorSubject,
        string keycloakSubjectId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keycloakSubjectId);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            WITH changed AS (
                UPDATE oryva.admin_provisioning
                SET keycloak_subject_id = @subject,
                    state = 'reconciliation_required',
                    updated_at = now()
                WHERE id = @id AND username = @username AND email = @email
                  AND requested_by_subject = @actor
                  AND state = 'reconciliation_required'
                  AND (keycloak_subject_id IS NULL OR keycloak_subject_id = @subject)
                RETURNING id, requested_by_subject
            )
            INSERT INTO oryva.admin_provisioning_audit
                (provisioning_id, event_type, actor_subject)
            SELECT id, 'subject_bound', requested_by_subject FROM changed
            RETURNING provisioning_id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("username", username);
        command.Parameters.AddWithValue("email", email);
        command.Parameters.AddWithValue("actor", actorSubject);
        command.Parameters.AddWithValue("subject", keycloakSubjectId);
        if (await command.ExecuteScalarAsync(cancellationToken) is null)
            throw new InvalidOperationException("Provisioning identity binding mismatch.");
    }

    /// <summary>
    /// Binds a reconciled Keycloak subject to an existing reservation.
    /// Never changes a different previously bound subject.
    /// </summary>
    public async Task BindReconciledSubjectAsync(
        Guid id, string subjectId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            WITH changed AS (
                UPDATE oryva.admin_provisioning
                SET keycloak_subject_id = @subject, updated_at = now()
                WHERE id = @id AND state = 'reconciliation_required'
                  AND (keycloak_subject_id IS NULL OR keycloak_subject_id = @subject)
                RETURNING id, requested_by_subject
            )
            INSERT INTO oryva.admin_provisioning_audit
                (provisioning_id, event_type, actor_subject)
            SELECT id, 'subject_bound', requested_by_subject FROM changed
            RETURNING provisioning_id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("subject", subjectId);
        if (await command.ExecuteScalarAsync(cancellationToken) is null)
            throw new InvalidOperationException("Reconciled subject binding denied.");
    }

    /// <summary>Transitions only a subject-bound reservation into prepared state.</summary>
    public async Task MarkPreparedAsync(
        Guid id, string subjectId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            WITH changed AS (
                UPDATE oryva.admin_provisioning
                SET state = 'prepared', updated_at = now()
                WHERE id = @id AND keycloak_subject_id = @subject
                  AND state = 'reconciliation_required'
                RETURNING id, requested_by_subject
            )
            INSERT INTO oryva.admin_provisioning_audit
                (provisioning_id, event_type, actor_subject)
            SELECT id, 'prepared', requested_by_subject FROM changed
            RETURNING provisioning_id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("subject", subjectId);
        if (await command.ExecuteScalarAsync(cancellationToken) is null)
            throw new InvalidOperationException("Admin provisioning prepared transition denied.");
    }

    public async Task MarkReconciliationRequiredAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            WITH changed AS (
                UPDATE oryva.admin_provisioning
                SET state = 'reconciliation_required', updated_at = now()
                WHERE id = @id AND state = 'reserved'
                RETURNING id, requested_by_subject
            )
            INSERT INTO oryva.admin_provisioning_audit
                (provisioning_id, event_type, actor_subject)
            SELECT id, 'reconciliation_required', requested_by_subject FROM changed
            RETURNING provisioning_id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        if (await command.ExecuteScalarAsync(cancellationToken) is null)
            throw new InvalidOperationException("Admin provisioning reservation is not pending.");
    }
}

public sealed record AdminProvisioningReservation(
    Guid Id, string Username, string Email, string RequestedBySubject);

public sealed record AdminProvisioningState(
    Guid Id, string Username, string Email, string RequestedBySubject,
    string? KeycloakSubjectId, string State);

public sealed record AdminProvisioningAuditEvent(
    long EventId, string EventType, string ActorSubject, DateTime OccurredAt);
