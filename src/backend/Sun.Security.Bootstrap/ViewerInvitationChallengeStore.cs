using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;
using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Internal, database-first email-ownership challenge primitives. No public
/// invitation endpoint, email delivery, credential enrollment or activation.
/// Callers MUST validate the signed JWT, exclusive realm role and subject.
/// This store additionally checks and locks the matching database-active issuer
/// inside the issuance transaction, so a stale or forged role cannot issue.
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
    public Task<ViewerInvitationIssue> IssueAsync(
        Guid viewerId, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default) =>
        IssueCoreAsync(viewerId, actorSubject, actorRole, null, cancellationToken);

    /// <summary>
    /// Issues a challenge and atomically queues its encrypted bearer token.
    /// Only metadata is returned. There is deliberately no SMTP dispatcher.
    /// </summary>
    public async Task<ViewerInvitationQueuedReceipt> IssueQueuedAsync(
        Guid viewerId, string actorSubject, string actorRole,
        ViewerInvitationOutboxCrypto encryption,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(encryption);
        var issued = await IssueCoreAsync(
            viewerId, actorSubject, actorRole, encryption, cancellationToken);
        return new ViewerInvitationQueuedReceipt(issued.Id, issued.ExpiresAtUtc);
    }

    private async Task<ViewerInvitationIssue> IssueCoreAsync(
        Guid viewerId, string actorSubject, string actorRole,
        ViewerInvitationOutboxCrypto? encryption,
        CancellationToken cancellationToken)
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

        // Defense in depth: an issuer's role string alone is never authority.
        // Hold a shared lock through issuance so a concurrent database-first
        // admin deactivation cannot commit before the invitation transaction.
        // The HTTP caller must independently validate the signed JWT and
        // exclusive realm role; this store cannot validate an untrusted token.
        var issuerSql = actorRole == "master"
            ? """
              SELECT 1 FROM oryva.master_bootstrap
              WHERE singleton_id = 1 AND state = 'active' AND subject_id = @subject
              FOR SHARE;
              """
            : """
              SELECT 1 FROM oryva.admin_provisioning
              WHERE state = 'active' AND keycloak_subject_id = @subject
              FOR SHARE;
              """;
        await using (var issuer = new NpgsqlCommand(issuerSql, connection, transaction))
        {
            issuer.Parameters.AddWithValue("subject", actorSubject);
            if (await issuer.ExecuteScalarAsync(cancellationToken) is null)
                throw new InvalidOperationException(
                    "Invitation issuer is not an active database-authorized master/admin.");
        }

        // This row lock serializes concurrent issuers for the same viewer.
        string email;
        string keycloakSubject;
        await using (var locked = new NpgsqlCommand("""
            SELECT email, keycloak_subject_id FROM oryva.viewer_accounts
            WHERE id = @id AND state = 'role_assigned'
              AND keycloak_subject_id IS NOT NULL
            FOR UPDATE;
            """, connection, transaction))
        {
            locked.Parameters.AddWithValue("id", viewerId);
            await using var reader = await locked.ExecuteReaderAsync(cancellationToken);
            if (!await reader.ReadAsync(cancellationToken))
                throw new InvalidOperationException(
                    "Only a subject-bound, role-assigned inactive viewer can receive a challenge.");
            email = reader.GetString(0);
            keycloakSubject = reader.GetString(1);
            if (string.IsNullOrWhiteSpace(keycloakSubject))
                throw new InvalidOperationException("Viewer Keycloak subject is missing.");
        }

        // A new invitation supersedes every outstanding browser exchange for
        // this viewer. This runs under the viewer row lock and commits atomically
        // with the new challenge, preventing old sessions surviving a reissue.
        await using (var revokeSessions = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_browser_sessions
            SET revoked_at = clock_timestamp()
            WHERE viewer_id = @viewer AND revoked_at IS NULL;
            """, connection, transaction))
        {
            revokeSessions.Parameters.AddWithValue("viewer", viewerId);
            await revokeSessions.ExecuteNonQueryAsync(cancellationToken);
        }

        // Revocation and its actor-attributed event share the issuance transaction.
        // A failed audit insert rolls back the revocation and new challenge.
        await using (var revoke = new NpgsqlCommand("""
            WITH revoked AS (
                UPDATE oryva.viewer_invitation_challenges
                SET revoked_at = now()
                WHERE viewer_id = @viewer AND consumed_at IS NULL AND revoked_at IS NULL
                RETURNING id
            )
            INSERT INTO oryva.viewer_invitation_audit
                (challenge_id, viewer_id, event_type, actor_subject, actor_role)
            SELECT id, @viewer, 'revoked', @actor, @role FROM revoked;
            """, connection, transaction))
        {
            revoke.Parameters.AddWithValue("viewer", viewerId);
            revoke.Parameters.AddWithValue("actor", actorSubject);
            revoke.Parameters.AddWithValue("role", actorRole);
            await revoke.ExecuteNonQueryAsync(cancellationToken);
        }

        // Reissue invalidates any still-pending encrypted delivery. Both
        // revocation and cancellation roll back if the new issuance fails.
        await using (var cancel = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_outbox AS delivery
            SET state = 'cancelled', cancelled_at = now(),
                lease_id = NULL, lease_expires_at = NULL
            FROM oryva.viewer_invitation_challenges AS challenge
            WHERE delivery.challenge_id = challenge.id
              AND challenge.viewer_id = @viewer AND delivery.state IN ('pending', 'leased');
            """, connection, transaction))
        {
            cancel.Parameters.AddWithValue("viewer", viewerId);
            await cancel.ExecuteNonQueryAsync(cancellationToken);
        }

        DateTime expiresAt;
        await using (var insert = new NpgsqlCommand("""
            INSERT INTO oryva.viewer_invitation_challenges
                (id, viewer_id, token_digest, recipient_email,
                 keycloak_subject_snapshot, issued_by_subject, issued_by_role,
                 created_at, expires_at)
            VALUES (@challenge, @viewer, @digest, @email,
                    @subject, @actor, @role, now(), now() + interval '15 minutes')
            RETURNING expires_at;
            """, connection, transaction))
        {
            insert.Parameters.AddWithValue("challenge", challengeId);
            insert.Parameters.AddWithValue("viewer", viewerId);
            insert.Parameters.AddWithValue("digest", digest);
            insert.Parameters.AddWithValue("email", email);
            insert.Parameters.AddWithValue("subject", keycloakSubject);
            insert.Parameters.AddWithValue("actor", actorSubject);
            insert.Parameters.AddWithValue("role", actorRole);
            expiresAt = (DateTime)(await insert.ExecuteScalarAsync(cancellationToken)
                ?? throw new InvalidOperationException("Challenge insertion returned no expiry."));
        }

        // A failure to encrypt or insert the outbox row aborts challenge
        // issuance and audit together; no plaintext token reaches PostgreSQL.
        if (encryption is not null)
        {
            var envelope = encryption.Encrypt(challengeId, viewerId, email, token);
            await using var queue = new NpgsqlCommand("""
                INSERT INTO oryva.viewer_invitation_outbox
                    (challenge_id, key_id, nonce, ciphertext, auth_tag)
                VALUES (@challenge, @key, @nonce, @ciphertext, @tag);
                """, connection, transaction);
            queue.Parameters.AddWithValue("challenge", challengeId);
            queue.Parameters.AddWithValue("key", envelope.KeyId);
            queue.Parameters.AddWithValue("nonce", envelope.Nonce);
            queue.Parameters.AddWithValue("ciphertext", envelope.Ciphertext);
            queue.Parameters.AddWithValue("tag", envelope.Tag);
            await queue.ExecuteNonQueryAsync(cancellationToken);
        }

        await using (var audit = new NpgsqlCommand("""
            INSERT INTO oryva.viewer_invitation_audit
                (challenge_id, viewer_id, event_type, actor_subject, actor_role)
            VALUES (@challenge, @viewer, 'issued', @actor, @role);
            """, connection, transaction))
        {
            audit.Parameters.AddWithValue("challenge", challengeId);
            audit.Parameters.AddWithValue("viewer", viewerId);
            audit.Parameters.AddWithValue("actor", actorSubject);
            audit.Parameters.AddWithValue("role", actorRole);
            await audit.ExecuteNonQueryAsync(cancellationToken);
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
        await using var transaction =
            (NpgsqlTransaction)await connection.BeginTransactionAsync(cancellationToken);
        // Serialize redemption with viewer deactivation or subject rebinding.
        // Without this lock a concurrent state transition could commit while
        // the UPDATE below reads an older viewer snapshot.
        await using (var viewerLock = new NpgsqlCommand("""
            SELECT 1 FROM oryva.viewer_accounts
            WHERE id = @viewer AND state = 'role_assigned'
              AND keycloak_subject_id IS NOT NULL
            FOR SHARE;
            """, connection, transaction))
        {
            viewerLock.Parameters.AddWithValue("viewer", viewerId);
            if (await viewerLock.ExecuteScalarAsync(cancellationToken) is null)
                return false;
        }

        Guid? consumedId;
        await using (var command = new NpgsqlCommand("""
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
              AND viewer.keycloak_subject_id = challenge.keycloak_subject_snapshot
              AND lower(viewer.email) = lower(challenge.recipient_email)
            RETURNING challenge.id;
            """, connection, transaction))
        {
            command.Parameters.AddWithValue("viewer", viewerId);
            command.Parameters.AddWithValue("digest", Digest(token));
            consumedId = await command.ExecuteScalarAsync(cancellationToken) as Guid?;
        }

        if (consumedId is not Guid challengeId)
            return false; // Disposing the transaction rolls back; no audit event.

        // Possession of a bearer token is not authenticated identity.
        // The audit intentionally has no actor, email, digest or token.
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

        // Possession consumes the bearer token and cancels any unsent copy.
        await using (var cancel = new NpgsqlCommand("""
            UPDATE oryva.viewer_invitation_outbox
            SET state = 'cancelled', cancelled_at = now(),
                lease_id = NULL, lease_expires_at = NULL
            WHERE challenge_id = @challenge AND state IN ('pending', 'leased');
            """, connection, transaction))
        {
            cancel.Parameters.AddWithValue("challenge", challengeId);
            await cancel.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return true;
    }
}

/// <summary>
/// Contains a short-lived bearer secret. Intentionally redacts ToString()
/// to avoid accidental token disclosure in structured or exception logs.
/// </summary>
public sealed class ViewerInvitationIssue(Guid id, string token, DateTime expiresAtUtc)
{
    public Guid Id { get; } = id;
    // Explicit trusted delivery handoff only; never a JSON/API response.
    [JsonIgnore]
    [IgnoreDataMember]
    public string Token { get; } = token;
    public DateTime ExpiresAtUtc { get; } = expiresAtUtc;
    public override string ToString() =>
        $"ViewerInvitationIssue(Id={Id}, ExpiresAtUtc={ExpiresAtUtc:O}, Token=[REDACTED])";
}
