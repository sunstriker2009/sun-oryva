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

try
{
    var prepared = await SeedAsync("prepared");
    await ExpectDeniedAsync(() => store.IssueAsync(prepared, "ci-master", "master"));
    Console.WriteLine("PASS unassigned viewer cannot receive invitation challenge");

    var viewer = await SeedAsync("role_assigned");
    var other = await SeedAsync("role_assigned");
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "ci-viewer", "viewer"));
    await ExpectDeniedAsync(() => store.IssueAsync(viewer, "", "admin"));
    Console.WriteLine("PASS non-management actors rejected");

    var first = await store.IssueAsync(viewer, "ci-master", "master");
    if (first.Token.Length != 43 || first.ToString().Contains(first.Token))
        throw new Exception("Challenge token generation or log redaction failed.");
    var second = await store.IssueAsync(viewer, "ci-admin", "admin");
    if (await store.ConsumeAsync(viewer, first.Token))
        throw new Exception("Reissued challenge did not revoke the previous token.");
    if (await store.ConsumeAsync(other, second.Token) ||
        await store.ConsumeAsync(viewer, "invalid") ||
        await store.ConsumeAsync(viewer, second.Token[..42]))
        throw new Exception("Wrong subject or malformed token was accepted.");
    if (!await store.ConsumeAsync(viewer, second.Token) ||
        await store.ConsumeAsync(viewer, second.Token))
        throw new Exception("One-time challenge was not consumed exactly once.");
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
}
