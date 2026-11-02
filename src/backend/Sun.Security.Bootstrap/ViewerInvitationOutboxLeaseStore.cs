using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Internal, non-dispatching claim coordinator for encrypted invitations.
/// This does not decrypt bearer material, send email or authorize activation.
/// The future SMTP handoff must independently revalidate under a lock and
/// address at-least-once delivery before it is permitted to send.
/// </summary>
public sealed class ViewerInvitationOutboxLeaseStore(NpgsqlDataSource dataSource)
{
    /// <summary>
    /// Atomically leases one currently eligible, unexpired invitation.
    /// PostgreSQL SKIP LOCKED prevents two workers claiming the same row.
    /// An expired lease may be reclaimed with a NEW fencing identifier.
    /// </summary>
    public async Task<ViewerInvitationLease?> ClaimNextAsync(
        CancellationToken cancellationToken = default)
    {
        var leaseId = Guid.NewGuid();
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            WITH eligible AS MATERIALIZED (
                SELECT delivery.challenge_id
                FROM oryva.viewer_invitation_outbox AS delivery
                JOIN oryva.viewer_invitation_challenges AS challenge
                    ON challenge.id = delivery.challenge_id
                JOIN oryva.viewer_accounts AS viewer ON viewer.id = challenge.viewer_id
                WHERE (
                    (delivery.state = 'pending'
                        AND delivery.next_attempt_at <= clock_timestamp())
                    OR (delivery.state = 'leased'
                        AND delivery.lease_expires_at <= clock_timestamp())
                )
                  AND delivery.attempt_count < 5
                  AND challenge.expires_at > clock_timestamp()
                  AND challenge.consumed_at IS NULL AND challenge.revoked_at IS NULL
                  AND viewer.state = 'role_assigned'
                  AND viewer.keycloak_subject_id = challenge.keycloak_subject_snapshot
                  AND lower(viewer.email) = lower(challenge.recipient_email)
                ORDER BY delivery.created_at, delivery.challenge_id
                LIMIT 1
                FOR UPDATE OF delivery SKIP LOCKED
            )
            UPDATE oryva.viewer_invitation_outbox AS delivery
            SET state = 'leased', lease_id = @lease,
                lease_expires_at = clock_timestamp() + interval '60 seconds',
                attempt_count = attempt_count + 1
            FROM eligible
            WHERE delivery.challenge_id = eligible.challenge_id
            RETURNING delivery.challenge_id, delivery.lease_expires_at;
            """, connection);
        command.Parameters.AddWithValue("lease", leaseId);
        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        if (!await reader.ReadAsync(cancellationToken)) return null;
        return new ViewerInvitationLease(reader.GetGuid(0), leaseId, reader.GetDateTime(1));
    }

    /// <summary>
    /// Releases only the current, unexpired lease. Wrong or stale lease IDs
    /// cannot mutate a later worker's claim. A retry has a fixed delay;
    /// attempts are capped at five and exhausted rows are cancelled by Sweep.
    /// </summary>
    public async Task<bool> ReleaseForRetryAsync(
        ViewerInvitationLease lease, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_outbox
            SET state = 'pending', lease_id = NULL, lease_expires_at = NULL,
                next_attempt_at = clock_timestamp() + interval '20 seconds'
            WHERE challenge_id = @challenge AND lease_id = @lease
              AND state = 'leased' AND lease_expires_at > clock_timestamp();
            """, connection);
        command.Parameters.AddWithValue("challenge", lease.ChallengeId);
        command.Parameters.AddWithValue("lease", lease.LeaseId);
        return await command.ExecuteNonQueryAsync(cancellationToken) == 1;
    }

    /// <summary>
    /// Cancels invalid, expired or exhausted deliveries, including stale leases.
    /// Does not send, reveal or consume any invitation token.
    /// </summary>
    public async Task<int> SweepInvalidAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_outbox AS delivery
            SET state = 'cancelled', cancelled_at = clock_timestamp(),
                lease_id = NULL, lease_expires_at = NULL
            FROM oryva.viewer_invitation_challenges AS challenge
            JOIN oryva.viewer_accounts AS viewer ON viewer.id = challenge.viewer_id
            WHERE delivery.challenge_id = challenge.id
              AND delivery.state IN ('pending', 'leased')
              AND (
                  challenge.expires_at <= clock_timestamp()
                  OR challenge.consumed_at IS NOT NULL
                  OR challenge.revoked_at IS NOT NULL
                  OR viewer.state <> 'role_assigned'
                  OR viewer.keycloak_subject_id IS DISTINCT FROM challenge.keycloak_subject_snapshot
                  OR lower(viewer.email) <> lower(challenge.recipient_email)
                  OR (delivery.attempt_count >= 5 AND
                      (delivery.state = 'pending' OR
                       delivery.lease_expires_at <= clock_timestamp()))
              );
            """, connection);
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }
}

/// <summary>Metadata-only fencing receipt; never includes bearer material.</summary>
public sealed record ViewerInvitationLease(
    Guid ChallengeId, Guid LeaseId, DateTime LeaseExpiresAtUtc);
