using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using Npgsql;
using Sun.Security.Bootstrap;

var connectionString = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("ORYVA_TEST_DATABASE_URL is required.");
var options = new NpgsqlConnectionStringBuilder(connectionString);
if (options.Host != "127.0.0.1" || options.Database != "oryva_e2e")
    throw new InvalidOperationException("Invitation E2E requires the isolated loopback CI database.");

await using var source = NpgsqlDataSource.Create(connectionString);
var store = new ViewerInvitationChallengeStore(source);
var seeded = new List<Guid>();
var seededAdmin = Guid.NewGuid();
var masterSeeded = false;
var adminSeeded = false;

async Task<Guid> SeedAsync(string state)
{
    var id = Guid.NewGuid();
    var name = "viewer-invite-" + id.ToString("N")[..12];
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand("""
        INSERT INTO oryva.viewer_accounts
            (id, username, email, requested_by_subject, requested_by_role,
             keycloak_subject_id, state)
        VALUES (@id, @name, @email, 'ci-master', 'master', @subject, @state);
        """, connection);
    command.Parameters.AddWithValue("id", id);
    command.Parameters.AddWithValue("name", name);
    command.Parameters.AddWithValue("email", name + "@example.invalid");
    command.Parameters.AddWithValue("subject", "ci-subject-" + id.ToString("N"));
    command.Parameters.AddWithValue("state", state);
    await command.ExecuteNonQueryAsync();
    seeded.Add(id);
    return id;
}

async Task ExecuteAsync(string sql, Guid id)
{
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand(sql, connection);
    command.Parameters.AddWithValue("id", id);
    await command.ExecuteNonQueryAsync();
}

async Task ExpectDeniedAsync(Func<Task> action)
{
    try { await action(); }
    catch (InvalidOperationException) { return; }
    catch (ArgumentException) { return; }
    throw new Exception("Unsafe invitation issuance was accepted.");
}

async Task<int> CountAuditAsync(Guid challengeId, string eventType)
{
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand("""
        SELECT count(*) FROM oryva.viewer_invitation_audit
        WHERE challenge_id = @challenge AND event_type = @event;
        """, connection);
    command.Parameters.AddWithValue("challenge", challengeId);
    command.Parameters.AddWithValue("event", eventType);
    return Convert.ToInt32(await command.ExecuteScalarAsync());
}

async Task AssertActorAsync(Guid challengeId, string eventType, string? subject, string? role)
{
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand("""
        SELECT actor_subject, actor_role FROM oryva.viewer_invitation_audit
        WHERE challenge_id = @challenge AND event_type = @event;
        """, connection);
    command.Parameters.AddWithValue("challenge", challengeId);
    command.Parameters.AddWithValue("event", eventType);
    await using var reader = await command.ExecuteReaderAsync();
    if (!await reader.ReadAsync() ||
        (reader.IsDBNull(0) ? null : reader.GetString(0)) != subject ||
        (reader.IsDBNull(1) ? null : reader.GetString(1)) != role)
        throw new Exception("Invitation audit actor or event was incorrect.");
}

try
{
    // Seed only isolated CI database actors; no Keycloak identity is enabled.
    // The real JWT validation boundary remains the responsibility of the API.
    await using (var connection = await source.OpenConnectionAsync())
    await using (var master = new NpgsqlCommand("""
        INSERT INTO oryva.master_bootstrap
            (singleton_id, state, subject_id, activated_at)
        VALUES (1, 'active', 'ci-master', now());
        """, connection))
    {
        await master.ExecuteNonQueryAsync();
        masterSeeded = true;
    }
    await using (var connection = await source.OpenConnectionAsync())
    await using (var admin = new NpgsqlCommand("""
        INSERT INTO oryva.admin_provisioning
            (id, username, email, requested_by_subject, keycloak_subject_id, state)
        VALUES (@id, @username, @email, 'ci-master', 'ci-admin', 'active');
        """, connection))
    {
        var name = "invitation-admin-" + seededAdmin.ToString("N");
        admin.Parameters.AddWithValue("id", seededAdmin);
        admin.Parameters.AddWithValue("username", name);
        admin.Parameters.AddWithValue("email", name + "@example.invalid");
        await admin.ExecuteNonQueryAsync();
        adminSeeded = true;
    }

    var prepared = await SeedAsync("prepared");
    await ExpectDeniedAsync(() => store.IssueAsync(prepared, "ci-master", "master"));
    Console.WriteLine("PASS unassigned viewer cannot receive invitation challenge");

    var viewer = await SeedAsync("role_assigned");
    var other = await SeedAsync("role_assigned");

    // The queued API returns metadata only; bearer material is encrypted in
    // the same transaction as the challenge and append-only issuance audit.
    var encryption = new ViewerInvitationOutboxCrypto(
        "ci-ephemeral-v1", RandomNumberGenerator.GetBytes(32));
    var queued = await store.IssueQueuedAsync(viewer, "ci-master", "master", encryption);
    async Task<(ViewerInvitationEncryptedToken Envelope, string Email, string State)> LoadOutboxAsync(Guid id)
    {
        await using var connection = await source.OpenConnectionAsync();
        await using var command = new NpgsqlCommand("""
            SELECT delivery.key_id, delivery.nonce, delivery.ciphertext,
                   delivery.auth_tag, challenge.recipient_email, delivery.state
            FROM oryva.viewer_invitation_outbox AS delivery
            JOIN oryva.viewer_invitation_challenges AS challenge
              ON challenge.id = delivery.challenge_id
            WHERE delivery.challenge_id = @id;
            """, connection);
        command.Parameters.AddWithValue("id", id);
        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
            throw new Exception("Encrypted outbox record was not committed.");
        return (new ViewerInvitationEncryptedToken(
            reader.GetString(0), reader.GetFieldValue<byte[]>(1),
            reader.GetFieldValue<byte[]>(2), reader.GetFieldValue<byte[]>(3)),
            reader.GetString(4), reader.GetString(5));
    }
    var (firstEnvelope, recipient, initialState) = await LoadOutboxAsync(queued.Id);
    if (initialState != "pending" || queued.ToString().Contains("Token", StringComparison.Ordinal))
        throw new Exception("Outbox receipt was not metadata-only.");
    var firstQueuedToken = encryption.Decrypt(queued.Id, viewer, recipient, firstEnvelope);
    if (firstQueuedToken.Length != 43)
        throw new Exception("Encrypted outbox token could not be recovered.");
    var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(firstQueuedToken)));
    await using (var connection = await source.OpenConnectionAsync())
    await using (var digestCommand = new NpgsqlCommand("""
        SELECT token_digest FROM oryva.viewer_invitation_challenges WHERE id = @id;
        """, connection))
    {
        digestCommand.Parameters.AddWithValue("id", queued.Id);
        if ((string?)await digestCommand.ExecuteScalarAsync() != digest)
            throw new Exception("Encrypted outbox token did not match challenge digest.");
    }
    try
    {
        encryption.Decrypt(queued.Id, other, recipient, firstEnvelope);
        throw new Exception("Outbox ciphertext accepted a substituted viewer.");
    }
    catch (CryptographicException) { }
    try
    {
        var tampered = firstEnvelope with { Tag = (byte[])firstEnvelope.Tag.Clone() };
        tampered.Tag[0] ^= 1;
        encryption.Decrypt(queued.Id, viewer, recipient, tampered);
        throw new Exception("Outbox accepted a tampered authentication tag.");
    }
    catch (CryptographicException) { }
    try
    {
        new ViewerInvitationOutboxCrypto("wrong-key", RandomNumberGenerator.GetBytes(32))
            .Decrypt(queued.Id, viewer, recipient, firstEnvelope);
        throw new Exception("Outbox accepted an incorrect key identifier.");
    }
    catch (CryptographicException) { }

    var queuedAgain = await store.IssueQueuedAsync(viewer, "ci-master", "master", encryption);
    if ((await LoadOutboxAsync(queued.Id)).State != "cancelled" ||
        (await LoadOutboxAsync(queuedAgain.Id)).State != "pending" ||
        await store.ConsumeAsync(viewer, firstQueuedToken))
        throw new Exception("Reissue did not atomically revoke and cancel previous delivery.");
    var (secondEnvelope, secondEmail, _) = await LoadOutboxAsync(queuedAgain.Id);
    var secondQueuedToken = encryption.Decrypt(queuedAgain.Id, viewer, secondEmail, secondEnvelope);
    if (!await store.ConsumeAsync(viewer, secondQueuedToken) ||
        (await LoadOutboxAsync(queuedAgain.Id)).State != "cancelled")
        throw new Exception("Consumption failed to cancel pending encrypted delivery.");

    // An outbox insertion failure must roll back challenge revocation and audit.
    var surviving = await store.IssueQueuedAsync(viewer, "ci-master", "master", encryption);
    await using (var connection = await source.OpenConnectionAsync())
    await using (var trigger = new NpgsqlCommand("""
        CREATE FUNCTION oryva.ci_reject_outbox() RETURNS trigger LANGUAGE plpgsql AS
        $fn$ BEGIN RAISE EXCEPTION 'CI simulated outbox failure'; END $fn$;
        CREATE TRIGGER ci_reject_outbox BEFORE INSERT ON oryva.viewer_invitation_outbox
        FOR EACH ROW EXECUTE FUNCTION oryva.ci_reject_outbox();
        """, connection))
        await trigger.ExecuteNonQueryAsync();
    try
    {
        try
        {
            await store.IssueQueuedAsync(viewer, "ci-master", "master", encryption);
            throw new Exception("Outbox failure unexpectedly allowed issuance.");
        }
        catch (PostgresException ex) when (ex.MessageText == "CI simulated outbox failure") { }
    }
    finally
    {
        await using var connection = await source.OpenConnectionAsync();
        await using var drop = new NpgsqlCommand("""
            DROP TRIGGER ci_reject_outbox ON oryva.viewer_invitation_outbox;
            DROP FUNCTION oryva.ci_reject_outbox();
            """, connection);
        await drop.ExecuteNonQueryAsync();
    }
    if ((await LoadOutboxAsync(surviving.Id)).State != "pending" ||
        await CountAuditAsync(surviving.Id, "revoked") != 0)
        throw new Exception("Outbox insertion failure left a revoked challenge.");
    Console.WriteLine("PASS encrypted atomic outbox, AEAD tamper and identity binding, reissue and rollback");

    // No SMTP sender exists: verify only fenced PostgreSQL claim/retry gates.
    // Cancel the earlier queued challenge so this isolated claim test has
    // exactly one eligible row.
    var (survivingEnvelope, survivingEmail, _) = await LoadOutboxAsync(surviving.Id);
    if (!await store.ConsumeAsync(viewer,
        encryption.Decrypt(surviving.Id, viewer, survivingEmail, survivingEnvelope)))
        throw new Exception("Failed to close prior queued invitation fixture.");
    var leasing = new ViewerInvitationOutboxLeaseStore(source);
    var leaseViewer = await SeedAsync("role_assigned");
    var leaseQueued = await store.IssueQueuedAsync(leaseViewer, "ci-master", "master", encryption);
    var claims = await Task.WhenAll(
        Enumerable.Range(0, 12).Select(_ => leasing.ClaimNextAsync()));
    var won = claims.Where(x => x is not null).ToArray();
    if (won.Length != 1 || won[0]!.ChallengeId != leaseQueued.Id ||
        await leasing.ClaimNextAsync() is not null)
        throw new Exception("Concurrent workers claimed the same invitation.");
    var firstLease = won[0]!;
    if (await leasing.ReleaseForRetryAsync(firstLease with { LeaseId = Guid.NewGuid() }))
        throw new Exception("Wrong lease fencing identifier released delivery.");
    if (!await leasing.ReleaseForRetryAsync(firstLease) ||
        await leasing.ReleaseForRetryAsync(firstLease) ||
        await leasing.ClaimNextAsync() is not null)
        throw new Exception("Lease release/retry delay was not enforced.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_outbox
        SET next_attempt_at = clock_timestamp() - interval '1 second'
        WHERE challenge_id = @id;
        """, leaseQueued.Id);
    var secondLease = await leasing.ClaimNextAsync()
        ?? throw new Exception("Released delivery could not be reclaimed.");
    if (secondLease.LeaseId == firstLease.LeaseId ||
        await leasing.ReleaseForRetryAsync(firstLease))
        throw new Exception("Stale lease mutated a newer claim.");
    // An expired lease may be reclaimed; the old worker is fenced out.
    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_outbox
        SET lease_expires_at = clock_timestamp() - interval '1 second'
        WHERE challenge_id = @id;
        """, leaseQueued.Id);
    var reclaimed = await leasing.ClaimNextAsync()
        ?? throw new Exception("Expired lease was not reclaimable.");
    if (reclaimed.LeaseId == secondLease.LeaseId ||
        await leasing.ReleaseForRetryAsync(secondLease))
        throw new Exception("Expired lease owner could modify reclaimed delivery.");
    var reissued = await store.IssueQueuedAsync(leaseViewer, "ci-admin", "admin", encryption);
    if ((await LoadOutboxAsync(leaseQueued.Id)).State != "cancelled" ||
        await leasing.ReleaseForRetryAsync(reclaimed))
        throw new Exception("Reissue did not fence and cancel a claimed delivery.");
    // Expiry is checked at claim time and by the invalid-delivery sweep.
    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_challenges
        SET created_at = clock_timestamp() - interval '1 hour',
            expires_at = clock_timestamp() - interval '50 minutes'
        WHERE id = @id;
        """, reissued.Id);
    if (await leasing.ClaimNextAsync() is not null ||
        await leasing.SweepInvalidAsync() < 1 ||
        (await LoadOutboxAsync(reissued.Id)).State != "cancelled")
        throw new Exception("Expired invitation was not cancelled.");
    var rebound = await store.IssueQueuedAsync(leaseViewer, "ci-master", "master", encryption);
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET keycloak_subject_id = 'ci-rebound'
        WHERE id = @id;
        """, leaseViewer);
    if (await leasing.ClaimNextAsync() is not null ||
        await leasing.SweepInvalidAsync() < 1 ||
        (await LoadOutboxAsync(rebound.Id)).State != "cancelled")
        throw new Exception("Subject-rebound invitation was eligible for delivery.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts
        SET keycloak_subject_id = 'ci-subject-' || replace(id::text, '-', '')
        WHERE id = @id;
        """, leaseViewer);
    var emailChanged = await store.IssueQueuedAsync(leaseViewer, "ci-master", "master", encryption);
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET email = 'wrong-recipient@example.invalid'
        WHERE id = @id;
        """, leaseViewer);
    if (await leasing.ClaimNextAsync() is not null ||
        await leasing.SweepInvalidAsync() < 1 ||
        (await LoadOutboxAsync(emailChanged.Id)).State != "cancelled")
        throw new Exception("Changed-recipient invitation was eligible for delivery.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET email = username || '@example.invalid'
        WHERE id = @id;
        """, leaseViewer);
    var exhausted = await store.IssueQueuedAsync(leaseViewer, "ci-master", "master", encryption);
    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_outbox SET attempt_count = 5
        WHERE challenge_id = @id;
        """, exhausted.Id);
    if (await leasing.ClaimNextAsync() is not null ||
        await leasing.SweepInvalidAsync() < 1 ||
        (await LoadOutboxAsync(exhausted.Id)).State != "cancelled")
        throw new Exception("Exhausted delivery was not cancelled.");
    Console.WriteLine("PASS fenced outbox claim concurrency, retry, reissue, expiry, identity and exhaustion");

    // Transaction-held SMTP acceptance handoff is only wired to a loopback
    // Mailpit sink. No real email, public endpoint, or Keycloak activation.
    using var mailpitApi = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    async Task<int> MailpitTotalAsync()
    {
        var json = await mailpitApi.GetStringAsync("http://127.0.0.1:8025/api/v1/messages");
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.GetProperty("total").GetInt32();
    }
    var mailViewer = await SeedAsync("role_assigned");
    var mailQueued = await store.IssueQueuedAsync(mailViewer, "ci-master", "master", encryption);
    var mailLease = await leasing.ClaimNextAsync()
        ?? throw new Exception("Eligible Mailpit delivery was not leased.");
    if (mailLease.ChallengeId != mailQueued.Id)
        throw new Exception("Mailpit test leased an unexpected challenge.");
    var mailHandoff = new ViewerInvitationSmtpHandoff(
        source, encryption, new LoopbackMailpitInvitationTransport());
    var beforeMail = await MailpitTotalAsync();
    if (await mailHandoff.TrySendAsync(mailLease with { LeaseId = Guid.NewGuid() }) ||
        await MailpitTotalAsync() != beforeMail)
        throw new Exception("Wrong lease allowed an SMTP message.");
    if (!await mailHandoff.TrySendAsync(mailLease))
        throw new Exception("Valid transaction-held Mailpit SMTP handoff was denied.");
    if (await MailpitTotalAsync() != beforeMail + 1 ||
        (await LoadOutboxAsync(mailQueued.Id)).State != "sent" ||
        await mailHandoff.TrySendAsync(mailLease) ||
        await leasing.ClaimNextAsync() is not null)
        throw new Exception("SMTP acceptance was not recorded exactly once.");
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT count(*) FROM oryva.viewer_invitation_delivery_audit
        WHERE challenge_id = @id AND event_type = 'smtp_accepted';
        """, connection))
    {
        command.Parameters.AddWithValue("id", mailQueued.Id);
        if (Convert.ToInt32(await command.ExecuteScalarAsync()) != 1)
            throw new Exception("SMTP acceptance audit was missing or duplicated.");
    }
    // Reissue revokes the sent invitation without changing immutable
    // acceptance evidence. A delivered email is never proof of activation.
    var afterSent = await store.IssueQueuedAsync(mailViewer, "ci-master", "master", encryption);
    if ((await LoadOutboxAsync(mailQueued.Id)).State != "sent" ||
        (await LoadOutboxAsync(afterSent.Id)).State != "pending")
        throw new Exception("Reissue changed historical SMTP acceptance state.");
    var (afterEnvelope, afterEmail, _) = await LoadOutboxAsync(afterSent.Id);
    if (!await store.ConsumeAsync(mailViewer,
        encryption.Decrypt(afterSent.Id, mailViewer, afterEmail, afterEnvelope)))
        throw new Exception("Could not close reissued SMTP test fixture.");

    // A transport error must not leak a bearer via the exception. It leaves
    // the lease retryable and does not falsely record SMTP acceptance.
    var failedViewer = await SeedAsync("role_assigned");
    var failedQueued = await store.IssueQueuedAsync(failedViewer, "ci-master", "master", encryption);
    var failedLease = await leasing.ClaimNextAsync()
        ?? throw new Exception("Failed SMTP fixture was not leased.");
    var (failedEnvelope, failedEmail, _) = await LoadOutboxAsync(failedQueued.Id);
    var failedCode = encryption.Decrypt(failedQueued.Id, failedViewer, failedEmail, failedEnvelope);
    var failingHandoff = new ViewerInvitationSmtpHandoff(
        source, encryption, new CiFailingInvitationTransport());
    try
    {
        await failingHandoff.TrySendAsync(failedLease);
        throw new Exception("Simulated ambiguous SMTP failure was accepted.");
    }
    catch (InvalidOperationException ex)
    {
        if (ex.Message.Contains(failedCode, StringComparison.Ordinal) ||
            !ex.Message.Contains("ambiguous", StringComparison.Ordinal))
            throw new Exception("SMTP exception was not safely redacted.");
    }
    if ((await LoadOutboxAsync(failedQueued.Id)).State != "leased" ||
        !await leasing.ReleaseForRetryAsync(failedLease) ||
        (await LoadOutboxAsync(failedQueued.Id)).State != "pending")
        throw new Exception("Failed SMTP transaction did not retain retryable state.");
    if (!await store.ConsumeAsync(failedViewer, failedCode))
        throw new Exception("Could not close failed SMTP test fixture.");
    // Post-claim changes must be independently revalidated at SMTP handoff,
    // not merely when a worker originally acquired its lease.
    var noMailBaseline = await MailpitTotalAsync();
    var disabledAtHandoff = await SeedAsync("role_assigned");
    var disabledQueued = await store.IssueQueuedAsync(
        disabledAtHandoff, "ci-master", "master", encryption);
    var disabledLease = await leasing.ClaimNextAsync()
        ?? throw new Exception("Disabled-at-handoff fixture was not leased.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET state = 'deactivation_pending'
        WHERE id = @id;
        """, disabledAtHandoff);
    if (await mailHandoff.TrySendAsync(disabledLease) ||
        await leasing.SweepInvalidAsync() < 1)
        throw new Exception("Deactivated viewer was permitted to receive SMTP.");
    var reboundAtHandoff = await SeedAsync("role_assigned");
    var reboundQueued = await store.IssueQueuedAsync(
        reboundAtHandoff, "ci-master", "master", encryption);
    var reboundLease = await leasing.ClaimNextAsync()
        ?? throw new Exception("Subject-rebound handoff fixture was not leased.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET keycloak_subject_id = 'substituted'
        WHERE id = @id;
        """, reboundAtHandoff);
    if (await mailHandoff.TrySendAsync(reboundLease) ||
        await leasing.SweepInvalidAsync() < 1)
        throw new Exception("Rebound viewer was permitted to receive SMTP.");
    var expiredAtHandoff = await SeedAsync("role_assigned");
    var expiredQueued = await store.IssueQueuedAsync(
        expiredAtHandoff, "ci-master", "master", encryption);
    var expiredLease = await leasing.ClaimNextAsync()
        ?? throw new Exception("Expired handoff fixture was not leased.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_outbox
        SET lease_expires_at = clock_timestamp() - interval '1 second'
        WHERE challenge_id = @id;
        """, expiredQueued.Id);
    if (await mailHandoff.TrySendAsync(expiredLease))
        throw new Exception("Expired lease was permitted to send SMTP.");
    var (expiredEnvelope, expiredEmail, _) = await LoadOutboxAsync(expiredQueued.Id);
    if (!await store.ConsumeAsync(expiredAtHandoff,
        encryption.Decrypt(expiredQueued.Id, expiredAtHandoff, expiredEmail, expiredEnvelope)))
        throw new Exception("Could not close expired handoff fixture.");
    try
    {
        _ = new LoopbackMailpitInvitationTransport("smtp.example.com");
        throw new Exception("External SMTP destination was accepted.");
    }
    catch (ArgumentException) { }
    if (await MailpitTotalAsync() != noMailBaseline)
        throw new Exception("Invalid handoff sent an unexpected SMTP message.");
    // Explicit, single-iteration dispatch is NOT a hosted service. The only
    // configured transport is the isolated loopback Mailpit test sink.
    var dispatcher = new ViewerInvitationDispatchOnce(leasing, mailHandoff);
    if (await dispatcher.RunOnceAsync() != ViewerInvitationDispatchResult.NoEligibleDelivery)
        throw new Exception("Empty dispatch unexpectedly found a deliverable invitation.");

    var dispatchViewer = await SeedAsync("role_assigned");
    var dispatchQueued = await store.IssueQueuedAsync(
        dispatchViewer, "ci-master", "master", encryption);
    var dispatchBefore = await MailpitTotalAsync();
    var dispatchOutcomes = await Task.WhenAll(
        Enumerable.Range(0, 8).Select(_ => dispatcher.RunOnceAsync()));
    if (dispatchOutcomes.Count(x => x == ViewerInvitationDispatchResult.RelayAccepted) != 1 ||
        dispatchOutcomes.Any(x => x != ViewerInvitationDispatchResult.RelayAccepted &&
                                  x != ViewerInvitationDispatchResult.NoEligibleDelivery) ||
        await MailpitTotalAsync() != dispatchBefore + 1 ||
        (await LoadOutboxAsync(dispatchQueued.Id)).State != "sent" ||
        await dispatcher.RunOnceAsync() != ViewerInvitationDispatchResult.NoEligibleDelivery)
        throw new Exception("Concurrent dispatch iterations did not accept exactly one SMTP message.");

    // A simulated SMTP error must be classified without exposing its bearer
    // and must be released through the fenced, delayed retry path.
    var retryViewer = await SeedAsync("role_assigned");
    var retryQueued = await store.IssueQueuedAsync(
        retryViewer, "ci-master", "master", encryption);
    var retryBefore = await MailpitTotalAsync();
    var failedDispatcher = new ViewerInvitationDispatchOnce(
        leasing, new ViewerInvitationSmtpHandoff(
            source, encryption, new CiFailingInvitationTransport()));
    if (await failedDispatcher.RunOnceAsync() !=
            ViewerInvitationDispatchResult.TransportRetryScheduled ||
        (await LoadOutboxAsync(retryQueued.Id)).State != "pending" ||
        await MailpitTotalAsync() != retryBefore ||
        await dispatcher.RunOnceAsync() != ViewerInvitationDispatchResult.NoEligibleDelivery)
        throw new Exception("Ambiguous SMTP failure bypassed delayed, fenced retry.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_outbox
        SET next_attempt_at = clock_timestamp() - interval '1 second'
        WHERE challenge_id = @id;
        """, retryQueued.Id);
    if (await dispatcher.RunOnceAsync() != ViewerInvitationDispatchResult.RelayAccepted ||
        (await LoadOutboxAsync(retryQueued.Id)).State != "sent" ||
        await MailpitTotalAsync() != retryBefore + 1)
        throw new Exception("Released invitation did not retry through guarded SMTP handoff.");

    // State change before dispatch is swept without decrypting or emailing.
    var deniedViewer = await SeedAsync("role_assigned");
    var deniedQueued = await store.IssueQueuedAsync(
        deniedViewer, "ci-master", "master", encryption);
    var deniedBefore = await MailpitTotalAsync();
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET state = 'deactivation_pending'
        WHERE id = @id;
        """, deniedViewer);
    if (await dispatcher.RunOnceAsync() != ViewerInvitationDispatchResult.NoEligibleDelivery ||
        (await LoadOutboxAsync(deniedQueued.Id)).State != "cancelled" ||
        await MailpitTotalAsync() != deniedBefore)
        throw new Exception("Dispatcher sent or retained a deactivated viewer invitation.");
    // Internal monitoring is aggregate-only: no mailbox, bearer or identity
    // is read or returned. Test each state transition against a baseline.
    var health = new ViewerInvitationOutboxHealthStore(source);
    var healthBefore = await health.ReadAsync();
    var healthViewer = await SeedAsync("role_assigned");
    var healthQueued = await store.IssueQueuedAsync(
        healthViewer, "ci-master", "master", encryption);
    var healthPending = await health.ReadAsync();
    if (healthPending.Pending != healthBefore.Pending + 1 ||
        healthPending.DuePending != healthBefore.DuePending + 1 ||
        healthPending.RelayAccepted != healthBefore.RelayAccepted)
        throw new Exception("Outbox health pending/due counters are incorrect.");
    var healthJson = JsonSerializer.Serialize(healthPending);
    if (healthJson.Contains(healthQueued.Id.ToString(), StringComparison.OrdinalIgnoreCase) ||
        healthJson.Contains("example.invalid", StringComparison.OrdinalIgnoreCase) ||
        healthJson.Contains("ciphertext", StringComparison.OrdinalIgnoreCase) ||
        healthJson.Contains("subject", StringComparison.OrdinalIgnoreCase))
        throw new Exception("Outbox health snapshot exposed per-invitation data.");

    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_outbox
        SET attempt_count = 2,
            next_attempt_at = clock_timestamp() + interval '1 hour'
        WHERE challenge_id = @id;
        """, healthQueued.Id);
    var healthRetry = await health.ReadAsync();
    if (healthRetry.RetryPending != healthBefore.RetryPending + 1 ||
        healthRetry.DuePending != healthBefore.DuePending)
        throw new Exception("Outbox health delayed retry counters are incorrect.");

    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_outbox
        SET state = 'leased', lease_id = gen_random_uuid(),
            lease_expires_at = clock_timestamp() - interval '1 second',
            attempt_count = 5
        WHERE challenge_id = @id;
        """, healthQueued.Id);
    var healthExpired = await health.ReadAsync();
    if (healthExpired.Leased != healthBefore.Leased + 1 ||
        healthExpired.ExpiredLeases != healthBefore.ExpiredLeases + 1 ||
        healthExpired.ExhaustedUnsent != healthBefore.ExhaustedUnsent + 1 ||
        healthExpired.Pending != healthBefore.Pending)
        throw new Exception("Outbox health expired/exhausted lease counters are incorrect.");
    if (await leasing.SweepInvalidAsync() < 1)
        throw new Exception("Exhausted monitoring fixture was not cancelled.");
    var healthAfter = await health.ReadAsync();
    if (healthAfter.Cancelled < healthBefore.Cancelled + 1 ||
        healthAfter.ExpiredLeases != healthBefore.ExpiredLeases ||
        healthAfter.ExhaustedUnsent != healthBefore.ExhaustedUnsent)
        throw new Exception("Outbox health cancellation counters are incorrect.");
    Console.WriteLine("PASS aggregate-only outbox health: due, retry, stale lease, exhaustion and cancellation");

    Console.WriteLine("PASS explicit Mailpit dispatch: concurrent single acceptance, delayed retry and deactivation sweep");

    Console.WriteLine("PASS isolated Mailpit SMTP acceptance, lease fencing, audit and ambiguous retry");



    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "ci-viewer", "viewer"));
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "", "admin"));
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "ci-intruder", "master"));
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "ci-intruder", "admin"));
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "ci-admin", "master"));
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "ci-master", "admin"));
    Console.WriteLine("PASS forged, inactive and mismatched management actors rejected");

    var first = await store.IssueAsync(viewer, "ci-master", "master");
    if (first.Token.Length != 43 || first.ToString().Contains(first.Token))
        throw new Exception("Challenge token generation or log redaction failed.");
    // A controller accidentally returning this object must never serialize
    // its bearer secret, including when boxed or nested in a response DTO.
    foreach (var serialized in new[]
    {
        JsonSerializer.Serialize(first),
        JsonSerializer.Serialize((object)first),
        JsonSerializer.Serialize(first, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
        JsonSerializer.Serialize(new { Invitation = first })
    })
    {
        if (serialized.Contains(first.Token, StringComparison.Ordinal) ||
            serialized.Contains("\"token\"", StringComparison.OrdinalIgnoreCase) ||
            !serialized.Contains(first.Id.ToString(), StringComparison.OrdinalIgnoreCase))
            throw new Exception("Invitation bearer secret was exposed in a JSON response.");
    }
    Console.WriteLine("PASS invitation bearer token excluded from JSON and log representations");

    var second = await store.IssueAsync(viewer, "ci-admin", "admin");
    if (await CountAuditAsync(first.Id, "issued") != 1 ||
        await CountAuditAsync(first.Id, "revoked") != 1 ||
        await CountAuditAsync(second.Id, "issued") != 1)
        throw new Exception("Issuance or reissue audit events were not committed.");
    await AssertActorAsync(first.Id, "issued", "ci-master", "master");
    await AssertActorAsync(first.Id, "revoked", "ci-admin", "admin");
    await AssertActorAsync(second.Id, "issued", "ci-admin", "admin");

    // Revoking an admin in PostgreSQL immediately denies new challenges,
    // and a denied reissue must not revoke the existing valid challenge.
    await ExecuteAsync("""
        UPDATE oryva.admin_provisioning SET state = 'deactivation_pending'
        WHERE id = @id;
        """, seededAdmin);
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "ci-admin", "admin"));
    await ExecuteAsync("""
        UPDATE oryva.admin_provisioning SET state = 'active'
        WHERE id = @id;
        """, seededAdmin);
    if (await CountAuditAsync(second.Id, "revoked") != 0)
        throw new Exception("Denied issuer unexpectedly revoked an outstanding challenge.");
    Console.WriteLine("PASS database-first admin revocation denies issuance without mutation");

    if (await store.ConsumeAsync(viewer, first.Token))
        throw new Exception("Reissued challenge did not revoke the previous token.");
    if (await store.ConsumeAsync(other, second.Token) ||
        await store.ConsumeAsync(viewer, "invalid") ||
        await store.ConsumeAsync(viewer, second.Token[..42]))
        throw new Exception("Wrong subject or malformed token was accepted.");
    if (!await store.ConsumeAsync(viewer, second.Token) ||
        await store.ConsumeAsync(viewer, second.Token))
        throw new Exception("One-time challenge was not consumed exactly once.");
    if (await CountAuditAsync(second.Id, "consumed") != 1)
        throw new Exception("Consumption was not audited exactly once.");
    await AssertActorAsync(second.Id, "consumed", null, null);
    Console.WriteLine("PASS reissue revokes, wrong subject fails, replay fails");

    var expiring = await store.IssueAsync(viewer, "ci-master", "master");
    await ExecuteAsync("""
        UPDATE oryva.viewer_invitation_challenges
        SET created_at = now() - interval '1 hour',
            expires_at = now() - interval '50 minutes'
        WHERE id = @id;
        """, expiring.Id);
    if (await store.ConsumeAsync(viewer, expiring.Token))
        throw new Exception("Expired invitation token was accepted.");
    Console.WriteLine("PASS expiry enforced by PostgreSQL time");

    var emailBound = await store.IssueAsync(viewer, "ci-master", "master");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET email = 'changed@example.invalid'
        WHERE id = @id;
        """, viewer);
    if (await store.ConsumeAsync(viewer, emailBound.Token))
        throw new Exception("Challenge remained valid after recipient email changed.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET email = username || '@example.invalid'
        WHERE id = @id;
        """, viewer);
    Console.WriteLine("PASS email snapshot binding enforced");

    // An email address alone is not an identity: a re-bound Keycloak subject
    // must never be allowed to redeem an earlier owner's invitation.
    var subjectBound = await store.IssueAsync(viewer, "ci-master", "master");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts
        SET keycloak_subject_id = 'ci-rebound-subject'
        WHERE id = @id;
        """, viewer);
    if (await store.ConsumeAsync(viewer, subjectBound.Token))
        throw new Exception("Invitation accepted after Keycloak subject rebinding.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts
        SET keycloak_subject_id = 'ci-subject-' || replace(id::text, '-', '')
        WHERE id = @id;
        """, viewer);
    if (!await store.ConsumeAsync(viewer, subjectBound.Token))
        throw new Exception("Original subject could not redeem unchanged invitation.");
    await using (var connection = await source.OpenConnectionAsync())
    await using (var snapshot = new NpgsqlCommand("""
        SELECT keycloak_subject_snapshot FROM oryva.viewer_invitation_challenges
        WHERE id = @id;
        """, connection))
    {
        snapshot.Parameters.AddWithValue("id", subjectBound.Id);
        if ((string?)await snapshot.ExecuteScalarAsync() != "ci-subject-" + viewer.ToString("N"))
            throw new Exception("Invitation did not retain the original subject snapshot.");
    }
    Console.WriteLine("PASS Keycloak subject rebinding fails closed; original subject remains bound");

    var disabled = await store.IssueAsync(viewer, "ci-admin", "admin");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET state = 'deactivation_pending'
        WHERE id = @id;
        """, viewer);
    if (await store.ConsumeAsync(viewer, disabled.Token))
        throw new Exception("Deactivated viewer challenge was accepted.");
    await ExecuteAsync("""
        UPDATE oryva.viewer_accounts SET state = 'role_assigned'
        WHERE id = @id;
        """, viewer);
    Console.WriteLine("PASS non-enrollment database states deny challenge redemption");

    var concurrent = await store.IssueAsync(viewer, "ci-master", "master");
    var attempts = await Task.WhenAll(
        Enumerable.Range(0, 16).Select(_ => store.ConsumeAsync(viewer, concurrent.Token)));
    if (attempts.Count(x => x) != 1)
        throw new Exception("Concurrent redemption did not have exactly one winner.");

    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT token_digest FROM oryva.viewer_invitation_challenges WHERE id = @id;
        """, connection))
    {
        command.Parameters.AddWithValue("id", concurrent.Id);
        var stored = (string?)await command.ExecuteScalarAsync();
        if (stored is null || stored.Contains(concurrent.Token, StringComparison.Ordinal))
            throw new Exception("Plaintext bearer token was persisted.");
    }
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT state FROM oryva.viewer_accounts WHERE id = @id;
        """, connection))
    {
        command.Parameters.AddWithValue("id", viewer);
        if ((string?)await command.ExecuteScalarAsync() != "role_assigned")
            throw new Exception("Invitation challenge unexpectedly activated a viewer.");
    }
    if (await CountAuditAsync(concurrent.Id, "consumed") != 1)
        throw new Exception("Concurrent consumption created duplicate or missing audit events.");

    // Force an audit uniqueness failure and verify the token remains unconsumed:
    // the state mutation and audit insert must be one database transaction.
    var rollback = await store.IssueAsync(viewer, "ci-master", "master");
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        INSERT INTO oryva.viewer_invitation_audit
            (challenge_id, viewer_id, event_type)
        VALUES (@challenge, @viewer, 'consumed');
        """, connection))
    {
        command.Parameters.AddWithValue("challenge", rollback.Id);
        command.Parameters.AddWithValue("viewer", viewer);
        await command.ExecuteNonQueryAsync();
    }
    try
    {
        await store.ConsumeAsync(viewer, rollback.Token);
        throw new Exception("Consumption unexpectedly succeeded despite audit conflict.");
    }
    catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
    {
        // Expected: the audit uniqueness constraint prevented commit.
    }
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT consumed_at FROM oryva.viewer_invitation_challenges
        WHERE id = @challenge;
        """, connection))
    {
        command.Parameters.AddWithValue("challenge", rollback.Id);
        if (await command.ExecuteScalarAsync() is not DBNull)
            throw new Exception("Challenge consumption survived failed audit insertion.");
    }
    Console.WriteLine("PASS append-only actor audit, exactly-once consumption and atomic rollback");
    Console.WriteLine("PASS concurrent consumption exactly once; no activation; digest only");
}
finally
{
    await using var connection = await source.OpenConnectionAsync();
    await using (var deleteOutbox = new NpgsqlCommand("""
        DELETE FROM oryva.viewer_invitation_outbox
        WHERE challenge_id IN (
            SELECT id FROM oryva.viewer_invitation_challenges
            WHERE viewer_id = ANY(@ids));
        """, connection))
    {
        deleteOutbox.Parameters.AddWithValue("ids", seeded.ToArray());
        await deleteOutbox.ExecuteNonQueryAsync();
    }
    await using (var deleteChallenges = new NpgsqlCommand("""
        DELETE FROM oryva.viewer_invitation_challenges WHERE viewer_id = ANY(@ids);
        """, connection))
    {
        deleteChallenges.Parameters.AddWithValue("ids", seeded.ToArray());
        await deleteChallenges.ExecuteNonQueryAsync();
    }
    await using (var deleteViewers = new NpgsqlCommand("""
        DELETE FROM oryva.viewer_accounts WHERE id = ANY(@ids);
        """, connection))
    {
        deleteViewers.Parameters.AddWithValue("ids", seeded.ToArray());
        await deleteViewers.ExecuteNonQueryAsync();
    }
    if (adminSeeded)
    {
        await using var deleteAdmin = new NpgsqlCommand("""
            DELETE FROM oryva.admin_provisioning WHERE id = @id;
            """, connection);
        deleteAdmin.Parameters.AddWithValue("id", seededAdmin);
        await deleteAdmin.ExecuteNonQueryAsync();
    }
    if (masterSeeded)
    {
        await using var deleteMaster = new NpgsqlCommand("""
            DELETE FROM oryva.master_bootstrap
            WHERE singleton_id = 1 AND subject_id = 'ci-master';
            """, connection);
        await deleteMaster.ExecuteNonQueryAsync();
    }
}

// Test-only transport: intentionally includes the secret in its original error
// to verify the handoff never exposes third-party SMTP exception text.
sealed class CiFailingInvitationTransport : IViewerInvitationMailTransport
{
    public Task SendAsync(string recipientEmail, string bearerCode, CancellationToken cancellationToken) =>
        throw new InvalidOperationException("SMTP ambiguous failure: " + bearerCode);
}
