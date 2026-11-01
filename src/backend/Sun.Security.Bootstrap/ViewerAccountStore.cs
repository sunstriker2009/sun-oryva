using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Read-only viewer authorization boundary. Never trusts Keycloak role alone.
/// No viewer activation or provisioning mutation is exposed by this class.
/// </summary>
public sealed class ViewerAccountStore(NpgsqlDataSource dataSource)
{
    public async Task<bool> IsActiveViewerSubjectAsync(
        string? subjectId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId)) return false;
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1 FROM oryva.viewer_accounts
                WHERE keycloak_subject_id = @subject AND state = 'active'
            );
            """, connection);
        command.Parameters.AddWithValue("subject", subjectId);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Viewer authorization query returned no result."));
    }
    /// <summary>Durably reserve a unique viewer identity before any Keycloak write.</summary>
    public async Task<ViewerAccountState> ReserveAsync(
        string username, string email, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        if (actorRole is not ("master" or "admin"))
            throw new ArgumentException("Only master or admin can request viewers.", nameof(actorRole));
        var id = Guid.NewGuid();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            INSERT INTO oryva.viewer_accounts
                (id, username, email, requested_by_subject, requested_by_role)
            VALUES (@id, @username, @email, @actor, @role)
            ON CONFLICT DO NOTHING
            RETURNING id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("username", username);
        command.Parameters.AddWithValue("email", email);
        command.Parameters.AddWithValue("actor", actorSubject);
        command.Parameters.AddWithValue("role", actorRole);
        if (await command.ExecuteScalarAsync(cancellationToken) is null)
            throw new ViewerReservationConflictException();
        return new ViewerAccountState(id, username, email, actorSubject, actorRole, null, "reserved");
    }

    public async Task<ViewerAccountState?> GetAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT id, username, email, requested_by_subject, requested_by_role,
                   keycloak_subject_id, state
            FROM oryva.viewer_accounts WHERE id = @id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new ViewerAccountState(
            reader.GetGuid(0), reader.GetString(1), reader.GetString(2),
            reader.GetString(3), reader.GetString(4),
            reader.IsDBNull(5) ? null : reader.GetString(5), reader.GetString(6));
    }

    /// <summary>
    /// Only a reserved, externally verified, disabled and unprivileged
    /// Keycloak subject can be marked prepared. Does not grant viewer access.
    /// </summary>
    public async Task MarkPreparedAsync(
        Guid id, string subjectId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            UPDATE oryva.viewer_accounts
            SET keycloak_subject_id = @subject, state = 'prepared', updated_at = now()
            WHERE id = @id AND state = 'reserved'
              AND (keycloak_subject_id IS NULL OR keycloak_subject_id = @subject)
            RETURNING id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("subject", subjectId);
        if (await command.ExecuteScalarAsync(cancellationToken) is null)
            throw new InvalidOperationException("Viewer preparation transition denied.");
    }


    /// <summary>Persist role-assignment intent and its actor before contacting Keycloak.</summary>
    public Task MarkRoleAssignmentPendingAsync(
        Guid id, string subjectId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default) =>
        TransitionWithAuditAsync(id, subjectId, "prepared", "role_assignment_pending",
            actorSubject, actorRole, cancellationToken);

    /// <summary>Commit the verified disabled viewer role and append its audit event.</summary>
    public Task MarkRoleAssignedAsync(
        Guid id, string subjectId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default) =>
        TransitionWithAuditAsync(id, subjectId, "role_assignment_pending", "role_assigned",
            actorSubject, actorRole, cancellationToken);

    private async Task TransitionWithAuditAsync(
        Guid id, string subjectId, string expectedState, string nextState,
        string actorSubject, string actorRole, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        if (actorRole is not ("master" or "admin"))
            throw new ArgumentException("Only active master or admin can transition viewer provisioning.", nameof(actorRole));
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            WITH changed AS (
                UPDATE oryva.viewer_accounts
                SET state = @next, updated_at = now()
                WHERE id = @id AND keycloak_subject_id = @subject AND state = @expected
                RETURNING id
            )
            INSERT INTO oryva.viewer_provisioning_audit
                (provisioning_id, event_type, actor_subject, actor_role)
            SELECT id, @next, @actor, @role FROM changed
            RETURNING provisioning_id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        command.Parameters.AddWithValue("subject", subjectId);
        command.Parameters.AddWithValue("expected", expectedState);
        command.Parameters.AddWithValue("next", nextState);
        command.Parameters.AddWithValue("actor", actorSubject);
        command.Parameters.AddWithValue("role", actorRole);
        if (await command.ExecuteScalarAsync(cancellationToken) is null)
            throw new InvalidOperationException("Viewer provisioning state transition denied.");
    }

    /// <summary>
    /// Commit activation intent and actor audit before any Keycloak enablement.
    /// The pending state must never authorize viewer endpoints.
    /// </summary>
    public Task MarkActivationPendingAsync(
        Guid id, string subjectId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default) =>
        TransitionWithAuditAsync(id, subjectId, "role_assigned", "activation_pending",
            actorSubject, actorRole, cancellationToken);

    /// <summary>
    /// Commit active state only after observing an enabled, owned and fully
    /// verified Keycloak viewer. The conditional transition is atomic with audit.
    /// </summary>
    public Task MarkActivatedAsync(
        Guid id, string subjectId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default) =>
        TransitionWithAuditAsync(id, subjectId, "activation_pending", "active",
            actorSubject, actorRole, cancellationToken);

    /// <summary>Durable revocation intent immediately denies viewer APIs.</summary>
    public Task MarkDeactivationPendingAsync(
        Guid id, string subjectId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default) =>
        TransitionWithAuditAsync(id, subjectId, "active", "deactivation_pending",
            actorSubject, actorRole, cancellationToken);

    /// <summary>Confirm owned Keycloak disablement and session logout.</summary>
    public Task MarkDeactivatedAsync(
        Guid id, string subjectId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default) =>
        TransitionWithAuditAsync(id, subjectId, "deactivation_pending", "deactivated",
            actorSubject, actorRole, cancellationToken);

    public async Task<IReadOnlyList<ViewerProvisioningAuditEvent>> GetAuditAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT event_id, event_type, actor_subject, actor_role, occurred_at
            FROM oryva.viewer_provisioning_audit
            WHERE provisioning_id = @id ORDER BY event_id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        var events = new List<ViewerProvisioningAuditEvent>();
        while (await reader.ReadAsync(cancellationToken))
            events.Add(new ViewerProvisioningAuditEvent(
                reader.GetInt64(0), reader.GetString(1), reader.GetString(2),
                reader.GetString(3), reader.GetFieldValue<DateTime>(4)));
        return events;
    }

}

public sealed record ViewerAccountState(
    Guid Id, string Username, string Email, string RequestedBySubject,
    string RequestedByRole, string? KeycloakSubjectId, string State);

public sealed class ViewerReservationConflictException : InvalidOperationException
{
    public ViewerReservationConflictException()
        : base("Viewer username or email is already reserved.") { }
}

public sealed record ViewerProvisioningAuditEvent(
    long EventId, string EventType, string ActorSubject, string ActorRole, DateTime OccurredAt);
