using System.Net;
using System.Net.Mail;
using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Trusted internal transport. Implementations must never log the bearer code,
/// must bound network time, and must report success only after SMTP DATA acceptance.
/// No HTTP controller should accept or instantiate this interface from user input.
/// </summary>
public interface IViewerInvitationMailTransport
{
    Task SendAsync(string recipientEmail, string bearerCode, CancellationToken cancellationToken);
}

/// <summary>
/// Transaction-held, fail-closed SMTP handoff. A live viewer lock serializes
/// deactivation/reissue; challenge and outbox locks serialize consumption and
/// lease reclamation. The transaction stays open until SMTP accepts the message.
/// SMTP and PostgreSQL cannot commit atomically: a crash after SMTP acceptance
/// can cause a duplicate email on retry. The challenge remains one-time-use.
/// </summary>
public sealed class ViewerInvitationSmtpHandoff(
    NpgsqlDataSource dataSource,
    ViewerInvitationOutboxCrypto crypto,
    IViewerInvitationMailTransport transport)
{
    public async Task<bool> TrySendAsync(
        ViewerInvitationLease lease, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(lease);
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction =
            (NpgsqlTransaction)await connection.BeginTransactionAsync(cancellationToken);

        Guid viewerId;
        await using (var lookup = new NpgsqlCommand("""
            SELECT viewer_id FROM oryva.viewer_invitation_challenges WHERE id = @challenge;
            """, connection, transaction))
        {
            lookup.Parameters.AddWithValue("challenge", lease.ChallengeId);
            if (await lookup.ExecuteScalarAsync(cancellationToken) is not Guid found)
                return false;
            viewerId = found;
        }

        // Lock viewer FIRST: issuance and deactivation also lock viewer before
        // touching the challenge or outbox, preventing lock-order inversion.
        await using (var viewerLock = new NpgsqlCommand("""
            SELECT 1 FROM oryva.viewer_accounts WHERE id = @viewer FOR SHARE;
            """, connection, transaction))
        {
            viewerLock.Parameters.AddWithValue("viewer", viewerId);
            if (await viewerLock.ExecuteScalarAsync(cancellationToken) is null)
                return false;
        }

        string recipient;
        ViewerInvitationEncryptedToken envelope;
        int attemptCount;
        await using (var gate = new NpgsqlCommand("""
            SELECT challenge.recipient_email, delivery.key_id, delivery.nonce,
                   delivery.ciphertext, delivery.auth_tag, delivery.attempt_count
            FROM oryva.viewer_invitation_outbox AS delivery
            JOIN oryva.viewer_invitation_challenges AS challenge
              ON challenge.id = delivery.challenge_id
            JOIN oryva.viewer_accounts AS viewer ON viewer.id = challenge.viewer_id
            WHERE delivery.challenge_id = @challenge
              AND delivery.state = 'leased' AND delivery.lease_id = @lease
              AND delivery.lease_expires_at > clock_timestamp() + interval '15 seconds'
              AND challenge.expires_at > clock_timestamp() + interval '15 seconds'
              AND challenge.revoked_at IS NULL AND challenge.consumed_at IS NULL
              AND viewer.id = @viewer AND viewer.state = 'role_assigned'
              AND viewer.keycloak_subject_id = challenge.keycloak_subject_snapshot
              AND lower(viewer.email) = lower(challenge.recipient_email)
            FOR UPDATE OF challenge, delivery;
            """, connection, transaction))
        {
            gate.Parameters.AddWithValue("challenge", lease.ChallengeId);
            gate.Parameters.AddWithValue("lease", lease.LeaseId);
            gate.Parameters.AddWithValue("viewer", viewerId);
            await using var reader = await gate.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                return false;
            recipient = reader.GetString(0);
            envelope = new ViewerInvitationEncryptedToken(
                reader.GetString(1), reader.GetFieldValue<byte[]>(2),
                reader.GetFieldValue<byte[]>(3), reader.GetFieldValue<byte[]>(4));
            attemptCount = reader.GetInt32(5);
        }

        // Decrypt only AFTER locks and live eligibility checks; never log code.
        var bearerCode = crypto.Decrypt(lease.ChallengeId, viewerId, recipient, envelope);
        using (var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            bounded.CancelAfter(TimeSpan.FromSeconds(10));
            try
            {
                await transport.SendAsync(recipient, bearerCode, bounded.Token);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception)
            {
                // Deliberately omit transport exception/inner exception: third-party
                // SMTP clients may include message content or recipient in errors.
                // The transaction rolls back; the lease can be retried/reclaimed.
                throw new InvalidOperationException(
                    "Invitation SMTP handoff failed; acceptance may be ambiguous.");
            }
        }

        await using (var mark = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_outbox
            SET state = 'sent', smtp_accepted_at = clock_timestamp(),
                lease_id = NULL, lease_expires_at = NULL
            WHERE challenge_id = @challenge AND state = 'leased' AND lease_id = @lease;
            """, connection, transaction))
        {
            mark.Parameters.AddWithValue("challenge", lease.ChallengeId);
            mark.Parameters.AddWithValue("lease", lease.LeaseId);
            if (await mark.ExecuteNonQueryAsync(cancellationToken) != 1)
                throw new InvalidOperationException("Invitation delivery lease changed during handoff.");
        }

        await using (var audit = new NpgsqlCommand("""
            INSERT INTO oryva.viewer_invitation_delivery_audit
                (id, challenge_id, event_type, attempt_count)
            VALUES (@id, @challenge, 'smtp_accepted', @attempts);
            """, connection, transaction))
        {
            audit.Parameters.AddWithValue("id", Guid.NewGuid());
            audit.Parameters.AddWithValue("challenge", lease.ChallengeId);
            audit.Parameters.AddWithValue("attempts", attemptCount);
            await audit.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return true;
    }
}

/// <summary>
/// Isolated Mailpit adapter ONLY. Explicit loopback validation prevents
/// accidental external delivery; not a production SMTP configuration.
/// </summary>
public sealed class LoopbackMailpitInvitationTransport
    : IViewerInvitationMailTransport
{
    private readonly string host;
    private readonly int port;

    public LoopbackMailpitInvitationTransport(string host = "127.0.0.1", int port = 1025)
    {
        if (!IPAddress.TryParse(host, out var address) || !IPAddress.IsLoopback(address))
            throw new ArgumentException("Mailpit SMTP must be an explicit loopback IP.", nameof(host));
        if (port is < 1 or > 65535)
            throw new ArgumentOutOfRangeException(nameof(port));
        this.host = host;
        this.port = port;
    }

    public async Task SendAsync(
        string recipientEmail, string bearerCode, CancellationToken cancellationToken)
    {
        using var message = new MailMessage("oryva-ci@example.invalid", recipientEmail)
        {
            Subject = "ORYVA isolated invitation handoff test",
            Body = "ORYVA one-time invitation code (test only): " + bearerCode,
            IsBodyHtml = false
        };
        using var client = new SmtpClient(host, port)
        {
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = false,
            EnableSsl = false // Safe ONLY because host is validated loopback.
        };
        await client.SendMailAsync(message, cancellationToken);
    }
}
