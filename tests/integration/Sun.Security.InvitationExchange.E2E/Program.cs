using System.Text.Json;
using Npgsql;
using Sun.Security.Bootstrap;

var connectionString = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("ORYVA_TEST_DATABASE_URL is required.");
var options = new NpgsqlConnectionStringBuilder(connectionString);
if (options.Host != "127.0.0.1" || options.Database != "oryva_e2e")
    throw new InvalidOperationException("Browser exchange E2E requires the isolated loopback CI database.");

await using var source = NpgsqlDataSource.Create(connectionString);
var invitations = new ViewerInvitationChallengeStore(source);
var exchange = new ViewerInvitationBrowserExchangeStore(source);
var viewers = new List<Guid>();
var masterSeeded = false;

async Task<Guid> SeedViewerAsync()
{
    var id = Guid.NewGuid();
    var name = "browser-exchange-" + id.ToString("N")[..12];
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand("""
        INSERT INTO oryva.viewer_accounts
            (id, username, email, requested_by_subject, requested_by_role,
             keycloak_subject_id, state)
        VALUES (@id, @name, @email, 'ci-master', 'master', @subject, 'role_assigned');
        """, connection);
    command.Parameters.AddWithValue("id", id);
    command.Parameters.AddWithValue("name", name);
    command.Parameters.AddWithValue("email", name + "@example.invalid");
    command.Parameters.AddWithValue("subject", "ci-browser-subject-" + id.ToString("N"));
    await command.ExecuteNonQueryAsync();
    viewers.Add(id);
    return id;
}

async Task ChangeViewerAsync(Guid viewerId, string column, string value)
{
    if (column is not ("email" or "keycloak_subject_id"))
        throw new InvalidOperationException("Unsafe test column.");
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand(
        $"UPDATE oryva.viewer_accounts SET {column} = @value WHERE id = @viewer;",
        connection);
    command.Parameters.AddWithValue("value", value);
    command.Parameters.AddWithValue("viewer", viewerId);
    await command.ExecuteNonQueryAsync();
}

async Task<string> GetViewerValueAsync(Guid viewerId, string column)
{
    if (column is not ("email" or "keycloak_subject_id" or "state"))
        throw new InvalidOperationException("Unsafe test column.");
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand(
        $"SELECT {column} FROM oryva.viewer_accounts WHERE id = @viewer;", connection);
    command.Parameters.AddWithValue("viewer", viewerId);
    return (string)(await command.ExecuteScalarAsync()
        ?? throw new Exception("Missing viewer."));
}

async Task<int> ConsumedEventsAsync(Guid challengeId)
{
    await using var connection = await source.OpenConnectionAsync();
    await using var command = new NpgsqlCommand("""
        SELECT count(*) FROM oryva.viewer_invitation_audit
        WHERE challenge_id = @challenge AND event_type = 'consumed';
        """, connection);
    command.Parameters.AddWithValue("challenge", challengeId);
    return Convert.ToInt32(await command.ExecuteScalarAsync());
}

try
{
    // The real Keycloak browser ceremony is NOT enabled here. These are
    // database-only fixtures in the isolated CI environment.
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        INSERT INTO oryva.master_bootstrap
            (singleton_id, state, subject_id, activated_at)
        VALUES (1, 'active', 'ci-master', now());
        """, connection))
    {
        await command.ExecuteNonQueryAsync();
        masterSeeded = true;
    }

    var viewer = await SeedViewerAsync();
    var other = await SeedViewerAsync();
    var invitation = await invitations.IssueAsync(viewer, "ci-master", "master");

    if (await exchange.ExchangeAsync(viewer, "invalid") is not null ||
        await exchange.ExchangeAsync(other, invitation.Token) is not null ||
        await exchange.IsLiveAsync(viewer, "invalid"))
        throw new Exception("Malformed or cross-viewer token was accepted.");

    var session = await exchange.ExchangeAsync(viewer, invitation.Token)
        ?? throw new Exception("Valid invitation could not be exchanged.");
    if (session.BrowserSecret.Length != 43 ||
        !await exchange.IsLiveAsync(viewer, session.BrowserSecret) ||
        await exchange.IsLiveAsync(other, session.BrowserSecret) ||
        await exchange.ExchangeAsync(viewer, invitation.Token) is not null ||
        await invitations.ConsumeAsync(viewer, invitation.Token) ||
        await ConsumedEventsAsync(invitation.Id) != 1)
        throw new Exception("One-time exchange, binding or audit failed.");

    var json = JsonSerializer.Serialize(new { Nested = (object)session },
        new JsonSerializerOptions(JsonSerializerDefaults.Web));
    if (json.Contains(session.BrowserSecret, StringComparison.Ordinal) ||
        session.ToString().Contains(session.BrowserSecret, StringComparison.Ordinal))
        throw new Exception("Browser secret leaked through serialization or ToString.");

    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT session_digest FROM oryva.viewer_invitation_browser_sessions
        WHERE id = @session;
        """, connection))
    {
        command.Parameters.AddWithValue("session", session.Id);
        var digest = (string?)await command.ExecuteScalarAsync();
        if (digest is null || digest.Length != 64 ||
            digest.Contains(session.BrowserSecret, StringComparison.Ordinal))
            throw new Exception("Browser session was not digest-only.");
    }

    // Reissue must invalidate the old browser secret, even after the original
    // invitation was consumed.
    var reissued = await invitations.IssueAsync(viewer, "ci-master", "master");
    if (await exchange.IsLiveAsync(viewer, session.BrowserSecret))
        throw new Exception("Reissue left an old browser exchange live.");
    var afterReissue = await exchange.ExchangeAsync(viewer, reissued.Token)
        ?? throw new Exception("Reissued challenge was rejected.");

    // A subject change and restoration must NOT revive a browser session.
    var originalSubject = await GetViewerValueAsync(viewer, "keycloak_subject_id");
    await ChangeViewerAsync(viewer, "keycloak_subject_id", "ci-substituted-subject");
    await ChangeViewerAsync(viewer, "keycloak_subject_id", originalSubject);
    if (await exchange.IsLiveAsync(viewer, afterReissue.BrowserSecret))
        throw new Exception("Subject restoration revived a revoked browser secret.");

    var emailInvite = await invitations.IssueAsync(viewer, "ci-master", "master");
    var emailSession = await exchange.ExchangeAsync(viewer, emailInvite.Token)
        ?? throw new Exception("Email-change fixture exchange failed.");
    var originalEmail = await GetViewerValueAsync(viewer, "email");
    await ChangeViewerAsync(viewer, "email", "changed-" + viewer.ToString("N") + "@example.invalid");
    await ChangeViewerAsync(viewer, "email", originalEmail);
    if (await exchange.IsLiveAsync(viewer, emailSession.BrowserSecret))
        throw new Exception("Email restoration revived a revoked browser secret.");

    // PostgreSQL conditional update is the cross-replica replay gate.
    var concurrentInvite = await invitations.IssueAsync(viewer, "ci-master", "master");
    var attempts = await Task.WhenAll(Enumerable.Range(0, 16)
        .Select(_ => exchange.ExchangeAsync(viewer, concurrentInvite.Token)));
    var winners = attempts.Where(x => x is not null).ToArray();
    if (winners.Length != 1 || await ConsumedEventsAsync(concurrentInvite.Id) != 1)
        throw new Exception("Concurrent exchange had more than one winner.");
    var winner = winners[0]!;
    if (!await exchange.IsLiveAsync(viewer, winner.BrowserSecret))
        throw new Exception("Concurrent winner was not live.");

    // Shorten expiry in CI without waiting five minutes.
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        UPDATE oryva.viewer_invitation_browser_sessions
        SET expires_at = created_at + interval '1 microsecond'
        WHERE id = @session;
        """, connection))
    {
        command.Parameters.AddWithValue("session", winner.Id);
        await command.ExecuteNonQueryAsync();
    }
    if (await exchange.IsLiveAsync(viewer, winner.BrowserSecret))
        throw new Exception("Expired browser exchange was accepted.");

    // An exchange-insert failure must roll back the invitation consumption,
    // consumed audit and outbox cancellation together.
    var rollbackInvite = await invitations.IssueAsync(viewer, "ci-master", "master");
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        CREATE FUNCTION oryva.ci_reject_browser_exchange()
        RETURNS trigger LANGUAGE plpgsql AS $fn$
        BEGIN RAISE EXCEPTION 'CI browser exchange insert failure'; END $fn$;
        CREATE TRIGGER ci_reject_browser_exchange
        BEFORE INSERT ON oryva.viewer_invitation_browser_sessions
        FOR EACH ROW EXECUTE FUNCTION oryva.ci_reject_browser_exchange();
        """, connection))
        await command.ExecuteNonQueryAsync();
    try
    {
        try
        {
            await exchange.ExchangeAsync(viewer, rollbackInvite.Token);
            throw new Exception("Failed browser exchange unexpectedly committed.");
        }
        catch (PostgresException ex) when (ex.MessageText == "CI browser exchange insert failure") { }
    }
    finally
    {
        await using var connection = await source.OpenConnectionAsync();
        await using var command = new NpgsqlCommand("""
            DROP TRIGGER ci_reject_browser_exchange
                ON oryva.viewer_invitation_browser_sessions;
            DROP FUNCTION oryva.ci_reject_browser_exchange();
            """, connection);
        await command.ExecuteNonQueryAsync();
    }
    if (await ConsumedEventsAsync(rollbackInvite.Id) != 0 ||
        await exchange.ExchangeAsync(viewer, rollbackInvite.Token) is null)
        throw new Exception("Failed browser exchange did not roll back atomically.");

    // The quota is PostgreSQL-backed, so concurrent replicas cannot bypass
    // the cap. Invalid-shaped and valid-shaped wrong tokens both count, and
    // a denied attempt must not consume the legitimate invitation.
    var throttledViewer = await SeedViewerAsync();
    var throttledInvitation = await invitations.IssueAsync(
        throttledViewer, "ci-master", "master");
    if (await exchange.ExchangeAsync(throttledViewer, "malformed") is not null)
        throw new Exception("Malformed quota fixture unexpectedly succeeded.");
    var wrongToken = new string('A', 43);
    var wrongAttempts = await Task.WhenAll(Enumerable.Range(0, 48)
        .Select(_ => exchange.ExchangeAsync(throttledViewer, wrongToken)));
    if (wrongAttempts.Any(x => x is not null))
        throw new Exception("Incorrect invitation token passed under contention.");
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        SELECT attempt_count FROM oryva.viewer_invitation_exchange_quotas
        WHERE viewer_id = @viewer;
        """, connection))
    {
        command.Parameters.AddWithValue("viewer", throttledViewer);
        if (Convert.ToInt32(await command.ExecuteScalarAsync()) != 33)
            throw new Exception("Concurrent quota attempts did not saturate at 33.");
    }
    if (await exchange.ExchangeAsync(throttledViewer, throttledInvitation.Token) is not null ||
        await ConsumedEventsAsync(throttledInvitation.Id) != 0)
        throw new Exception("Saturated quota consumed a legitimate invitation.");
    await using (var connection = await source.OpenConnectionAsync())
    await using (var command = new NpgsqlCommand("""
        UPDATE oryva.viewer_invitation_exchange_quotas
        SET window_started_at = clock_timestamp() - interval '2 minutes'
        WHERE viewer_id = @viewer;
        """, connection))
    {
        command.Parameters.AddWithValue("viewer", throttledViewer);
        await command.ExecuteNonQueryAsync();
    }
    var recovered = await exchange.ExchangeAsync(throttledViewer, throttledInvitation.Token);
    if (recovered is null ||
        !await exchange.IsLiveAsync(throttledViewer, recovered.BrowserSecret) ||
        await ConsumedEventsAsync(throttledInvitation.Id) != 1)
        throw new Exception("Quota window rollover did not restore valid exchange.");

    if (await GetViewerValueAsync(viewer, "state") != "role_assigned")
        throw new Exception("Browser exchange changed viewer activation state.");

    Console.WriteLine("PASS browser exchange one-time replay, cross-viewer denial, digest-only storage");
    Console.WriteLine("PASS reissue and change-away/back revocation, expiry, 16-way concurrency");
    Console.WriteLine("PASS transactional rollback, append-only consumption audit, no activation");
    Console.WriteLine("PASS 48-way distributed quota contention, denial persistence, 60s rollover");
}
finally
{
    await using var connection = await source.OpenConnectionAsync();
    await using (var command = new NpgsqlCommand("""
        DELETE FROM oryva.viewer_invitation_browser_sessions
        WHERE viewer_id = ANY(@ids);
        """, connection))
    {
        command.Parameters.AddWithValue("ids", viewers.ToArray());
        await command.ExecuteNonQueryAsync();
    }
    await using (var command = new NpgsqlCommand("""
        DELETE FROM oryva.viewer_invitation_outbox
        WHERE challenge_id IN
            (SELECT id FROM oryva.viewer_invitation_challenges
             WHERE viewer_id = ANY(@ids));
        """, connection))
    {
        command.Parameters.AddWithValue("ids", viewers.ToArray());
        await command.ExecuteNonQueryAsync();
    }
    await using (var command = new NpgsqlCommand("""
        DELETE FROM oryva.viewer_invitation_challenges
        WHERE viewer_id = ANY(@ids);
        """, connection))
    {
        command.Parameters.AddWithValue("ids", viewers.ToArray());
        await command.ExecuteNonQueryAsync();
    }
    await using (var command = new NpgsqlCommand("""
        DELETE FROM oryva.viewer_accounts WHERE id = ANY(@ids);
        """, connection))
    {
        command.Parameters.AddWithValue("ids", viewers.ToArray());
        await command.ExecuteNonQueryAsync();
    }
    if (masterSeeded)
    {
        await using var command = new NpgsqlCommand("""
            DELETE FROM oryva.master_bootstrap
            WHERE singleton_id = 1 AND subject_id = 'ci-master';
            """, connection);
        await command.ExecuteNonQueryAsync();
    }
}
