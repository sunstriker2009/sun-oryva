using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Internal read-only aggregate health counters for invitation delivery.
/// Not registered as an HTTP endpoint, worker or background service.
/// </summary>
public sealed class ViewerInvitationOutboxHealthStore(NpgsqlDataSource dataSource)
{
    /// <summary>
    /// Single-statement PostgreSQL snapshot using server time. Counts are
    /// diagnostic, not permission to dispatch. Failures propagate.
    /// </summary>
    public async Task<ViewerInvitationOutboxHealthSnapshot> ReadAsync(
        CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT statement_timestamp(),
                count(*) FILTER (WHERE state = 'pending'),
                count(*) FILTER (WHERE state = 'pending'
                    AND next_attempt_at <= statement_timestamp()),
                count(*) FILTER (WHERE state = 'leased'),
                count(*) FILTER (WHERE state = 'leased'
                    AND lease_expires_at <= statement_timestamp()),
                count(*) FILTER (WHERE state = 'pending' AND attempt_count > 0),
                count(*) FILTER (WHERE state IN ('pending', 'leased')
                    AND attempt_count >= 5),
                count(*) FILTER (WHERE state = 'sent'),
                count(*) FILTER (WHERE state = 'cancelled')
            FROM oryva.viewer_invitation_outbox;
            """, connection);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken))
            throw new InvalidOperationException("Invitation outbox health snapshot was unavailable.");

        return new ViewerInvitationOutboxHealthSnapshot(
            reader.GetDateTime(0),
            reader.GetInt64(1),
            reader.GetInt64(2),
            reader.GetInt64(3),
            reader.GetInt64(4),
            reader.GetInt64(5),
            reader.GetInt64(6),
            reader.GetInt64(7),
            reader.GetInt64(8));
    }
}

/// <summary>
/// Aggregate-only monitoring data. Do not add per-invitation identifiers
/// or recipient dimensions to this operational contract.
/// </summary>
public sealed record ViewerInvitationOutboxHealthSnapshot(
    DateTime CapturedAtUtc,
    long Pending,
    long DuePending,
    long Leased,
    long ExpiredLeases,
    long RetryPending,
    long ExhaustedUnsent,
    long RelayAccepted,
    long Cancelled);
