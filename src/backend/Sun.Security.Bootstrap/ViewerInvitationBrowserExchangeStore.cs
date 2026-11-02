using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Internal invitation bearer exchange into a separate five-minute browser
/// secret. No HTTP endpoint, cookie, credential mutation, emailVerified update
/// or Keycloak activation is provided. The future browser boundary MUST add
/// origin/CSRF protection, HttpOnly/Secure/SameSite cookies, rate limits and
/// an atomic, independently reviewed credential-completion ceremony.
/// </summary>
public sealed class ViewerInvitationBrowserExchangeStore(NpgsqlDataSource dataSource)
{
    private static bool IsTokenShape(string? value)
    {
        if (value is null || value.Length != 43) return false;
        foreach (var c in value)
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c is '-' or '_'))
                return false;
        return true;
    }

    private static string Digest(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(value)));

    private static string NewSecret() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>
    /// Consumes exactly one valid invitation and atomically creates a separate
    /// digest-only browser secret. Null is a generic denial. This proves
    /// possession of the invitation code, NOT Keycloak email verification or
    /// eligibility for credential enrollment/activation.
    /// </summary>
    public async Task<ViewerInvitationBrowserExchange?> ExchangeAsync(
        Guid viewerId, string? invitationToken,
        CancellationToken cancellationToken = default)
    {
        if (!IsTokenShape(invitationToken)) return null;

        var sessionId = Guid.NewGuid();
        var browserSecret = NewSecret();

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction =
            (NpgsqlTransaction)await connection.BeginTransactionAsync(cancellationToken);

        // Consistent viewer -> challenge -> outbox lock order, shared with
        // issuance, deactivation and SMTP handoff.
        await using (var viewerLock = new NpgsqlCommand("""
            SELECT 1 FROM oryva.viewer_accounts
            WHERE id = @viewer AND state = 'role_assigned'
              AND keycloak_subject_id IS NOT NULL
            FOR SHARE;
            """, connection, transaction))
        {
            viewerLock.Parameters.AddWithValue("viewer", viewerId);
            if (await viewerLock.ExecuteScalarAsync(cancellationToken) is null)
                return null;
        }

        Guid challengeId;
        await using (var consume = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_challenges AS challenge
            SET consumed_at = clock_timestamp()
            FROM oryva.viewer_accounts AS viewer
            WHERE challenge.viewer_id = viewer.id
              AND viewer.id = @viewer
              AND challenge.token_digest = @digest
              AND challenge.consumed_at IS NULL
              AND challenge.revoked_at IS NULL
              AND challenge.expires_at > clock_timestamp()
              AND viewer.state = 'role_assigned'
              AND viewer.keycloak_subject_id = challenge.keycloak_subject_snapshot
              AND lower(viewer.email) = lower(challenge.recipient_email)
            RETURNING challenge.id;
            """, connection, transaction))
        {
            consume.Parameters.AddWithValue("viewer", viewerId);
            consume.Parameters.AddWithValue("digest", Digest(invitationToken!));
            if (await consume.ExecuteScalarAsync(cancellationToken) is not Guid id)
                return null;
            challengeId = id;
        }

        // Audit, exchange creation, invitation consumption and pending SMTP
        // cancellation commit or roll back together.
        await using (var audit = new NpgsqlCommand("""
            INSERT INTO oryva.viewer_invitation_audit
                (challenge_id, viewer_id, event_type)
            VALUES (@challenge, @viewer, 'consumed');
            """, connection, transaction))
        {
            audit.Parameters.AddWithValue("challenge", challengeId);
            audit.Parameters.AddWithValue("viewer", viewerId);
            await audit.ExecuteNonQueryAsync(cancellationToken);
        }

        DateTime expiresAtUtc;
        await using (var insert = new NpgsqlCommand("""
            WITH stamp AS MATERIALIZED (SELECT clock_timestamp() AS issued_at)
            INSERT INTO oryva.viewer_invitation_browser_sessions
                (id, challenge_id, viewer_id, session_digest,
                 subject_snapshot, created_at, expires_at)
            SELECT @session, challenge.id, @viewer, @digest,
                   challenge.keycloak_subject_snapshot,
                   stamp.issued_at, stamp.issued_at + interval '5 minutes'
            FROM oryva.viewer_invitation_challenges AS challenge
            CROSS JOIN stamp
            WHERE challenge.id = @challenge AND challenge.viewer_id = @viewer
            RETURNING expires_at;
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue("session", sessionId);
            insert.Parameters.AddWithValue("challenge", challengeId);
            insert.Parameters.AddWithValue("viewer", viewerId);
            insert.Parameters.AddWithValue("digest", Digest(browserSecret));
            expiresAtUtc = (DateTime)(await insert.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Browser exchange insertion failed."));
        }

        await using (var cancel = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_outbox
            SET state = 'cancelled', cancelled_at = clock_timestamp(),
                lease_id = NULL, lease_expires_at = NULL
            WHERE challenge_id = @challenge AND state IN ('pending', 'leased');
            """, connection, transaction))
        {
            cancel.Parameters.AddWithValue("challenge", challengeId);
            await cancel.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return new ViewerInvitationBrowserExchange(sessionId, browserSecret, expiresAtUtc);
    }

    /// <summary>
    /// Point-in-time INTERNAL inspection only. Never use this as authentication,
    /// a password-write authorization, or an activation gate. A future
    /// credential transaction must recheck the identity under its own locks.
    /// </summary>
    public async Task<bool> IsLiveAsync(
        Guid viewerId, string? browserSecret,
        CancellationToken cancellationToken = default)
    {
        if (!IsTokenShape(browserSecret)) return false;
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT 1
            FROM oryva.viewer_invitation_browser_sessions AS session
            JOIN oryva.viewer_invitation_challenges AS challenge
              ON challenge.id = session.challenge_id
             AND challenge.viewer_id = session.viewer_id
            JOIN oryva.viewer_accounts AS viewer ON viewer.id = session.viewer_id
            WHERE session.viewer_id = @viewer
              AND session.session_digest = @digest
              AND session.revoked_at IS NULL
              AND session.expires_at > clock_timestamp()
              AND challenge.consumed_at IS NOT NULL
              AND challenge.revoked_at IS NULL
              AND viewer.state = 'role_assigned'
              AND viewer.keycloak_subject_id = session.subject_snapshot
              AND challenge.keycloak_subject_snapshot = session.subject_snapshot
              AND lower(viewer.email) = lower(challenge.recipient_email)
            LIMIT 1;
            """, connection);
        command.Parameters.AddWithValue("viewer", viewerId);
        command.Parameters.AddWithValue("digest", Digest(browserSecret!));
        return await command.ExecuteScalarAsync(cancellationToken) is not null;
    }
}

/// <summary>
/// Trusted handoff only. The secret is never a JSON response, log property,
/// database value or proof of verified Keycloak email/credential enrollment.
/// </summary>
public sealed class ViewerInvitationBrowserExchange(
    Guid id, string browserSecret, DateTime expiresAtUtc)
{
    public Guid Id { get; } = id;
    [JsonIgnore]
    [IgnoreDataMember]
    public string BrowserSecret { get; } = browserSecret;
    public DateTime ExpiresAtUtc { get; } = expiresAtUtc;
    public override string ToString() =>
        $"ViewerInvitationBrowserExchange(Id={Id}, ExpiresAtUtc={ExpiresAtUtc:O}, Secret=[REDACTED])";
}
