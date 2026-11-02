using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Internal, database-first email-ownership challenge primitives. No public
/// invitation endpoint, email delivery, credential enrollment or activation.
/// Callers MUST separately authorize the database-active master/admin actor.
/// </summary>
public sealed class ViewerInvitationChallengeStore(NpgsqlDataSource dataSource)
{
    private static string Digest(string token) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    /// <summary>
    /// Generates a CSPRNG 256-bit bearer token and persists only its digest.
    /// Reissuing atomically revokes the previous unconsumed challenge.
    /// The returned secret must be delivered only by a future approved mailer,
    /// never logged or returned from an administrative API.
    /// </summary>
    public async Task<ViewerInvitationIssue> IssueAsync(
        Guid viewerId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        if (actorRole is not ("master" or "admin"))
            throw new ArgumentException("Only master/admin may issue a challenge.", nameof(actorRole));

        var token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var digest = Digest(token);
        var challengeId = Guid.NewGuid();

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var transaction =
            (NpgsqlTransaction)await connection.BeginTransactionAsync(cancellationToken);

        // This row lock serializes concurrent issuers for the same viewer.
        string email;
        await using (var locked = new NpgsqlCommand("""
            SELECT email FROM oryva.viewer_accounts
            WHERE id = @id AND state = 'role_assigned'
              AND keycloak_subject_id IS NOT NULL
            FOR UPDATE;
            """, connection, transaction))
        {
            locked.Parameters.AddWithValue("id", viewerId);
            email = (string?)await locked.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException(
                    "Only a subject-bound, role-assigned inactive viewer can receive a challenge.");
        }

        await using (var revoke = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_challenges
            SET revoked_at = now()
            WHERE viewer_id = @id AND consumed_at IS NULL AND revoked_at IS NULL;
            """, connection, transaction))
        {
            revoke.Parameters.AddWithValue("id", viewerId);
            await revoke.ExecuteNonQueryAsync(cancellationToken);
        }

        DateTime expiresAt;
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO oryva.viewer_invitation_challenges
                (id, viewer_id, token_digest, recipient_email,
                 issued_by_subject, issued_by_role, created_at, expires_at)
            VALUES (@challenge, @viewer, @digest, @email,
                    @actor, @role, now(), now() + interval '15 minutes')
            RETURNING expires_at;
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue("challenge", challengeId);
            insert.Parameters.AddWithValue("viewer", viewerId);
            insert.Parameters.AddWithValue("digest", digest);
            insert.Parameters.AddWithValue("email", email);
            insert.Parameters.AddWithValue("actor", actorSubject);
            insert.Parameters.AddWithValue("role", actorRole);
            expiresAt = (DateTime)(await insert.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Challenge insertion returned no expiry."));
        }

        await transaction.CommitAsync(cancellationToken);
        return new ViewerInvitationIssue(challengeId, token, expiresAt);
    }

    /// <summary>
    /// Atomically records one-time possession of a challenge. This does NOT
    /// verify a Keycloak email, set a password, enable a user or grant access.
    /// Future enrollment must use a separately reviewed, bound ceremony.
    /// </summary>
    public async Task<bool> ConsumeAsync(
        Guid viewerId, string? token, CancellationToken cancellationToken = default)
    {
        // Reject malformed tokens without a database lookup.
        if (token is null || token.Length != 43) return false;
        foreach (var c in token)
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c is '-' or '_'))
                return false;

        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_challenges AS challenge
            SET consumed_at = now()
            FROM oryva.viewer_accounts AS viewer
            WHERE challenge.viewer_id = viewer.id
              AND viewer.id = @viewer
              AND challenge.token_digest = @digest
              AND challenge.consumed_at IS NULL
              AND challenge.revoked_at IS NULL
              AND challenge.expires_at > clock_timestamp()
              AND viewer.state = 'role_assigned'
              AND viewer.keycloak_subject_id IS NOT NULL
              AND lower(viewer.email) = lower(challenge.recipient_email)
            RETURNING challenge.id;
            """, connection);
        command.Parameters.AddWithValue("viewer", viewerId);
        command.Parameters.AddWithValue("digest", Digest(token));
        return await command.ExecuteScalarAsync(cancellationToken) is Guid;
    }
}

/// <summary>
/// Contains a short-lived bearer secret. Intentionally redacts ToString()
/// to avoid accidental token disclosure in structured or exception logs.
/// </summary>
public sealed class ViewerInvitationIssue(Guid id, string token, DateTime expiresAtUtc)
{
    public Guid Id { get; } = id;
    public string Token { get; } = token;
    public DateTime ExpiresAtUtc { get; } = expiresAtUtc;
    public override string ToString() =>
        $"ViewerInvitationIssue(Id={Id}, ExpiresAtUtc={ExpiresAtUtc:O}, Token=[REDACTED])";
}
