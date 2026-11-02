using System.Text.Json;
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
