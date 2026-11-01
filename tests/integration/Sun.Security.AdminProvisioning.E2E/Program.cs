using Npgsql;
using Sun.Security.Bootstrap;

var dsn = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("Missing ORYVA_TEST_DATABASE_URL");
var secret = Environment.GetEnvironmentVariable("ORYVA_TEST_CLIENT_SECRET")
    ?? throw new InvalidOperationException("Missing ORYVA_TEST_CLIENT_SECRET");
await using var source = NpgsqlDataSource.Create(dsn);
var store = new AdminProvisioningStore(source);
using var http = KeycloakHttpClientFactory.Create();
var keycloak = new KeycloakManagementClient(http, new KeycloakManagementOptions
{
    BaseAddress = new Uri("http://127.0.0.1:8080/"),
    ClientId = "oryva-e2e-bootstrap",
    ClientSecret = secret
});
var username = "admin-candidate-" + Guid.NewGuid().ToString("N")[..12];
var email = username + "@example.invalid";
const string actor = "e2e-master-subject";
var reservations = await Task.WhenAll(
    Enumerable.Range(0, 12).Select(async _ =>
    {
        try { return await store.ReserveAsync(username, email, actor); }
        catch (InvalidOperationException) { return null; }
    }));
var accepted = reservations.Where(x => x is not null).ToArray();
if (accepted.Length != 1)
    throw new Exception($"Expected one reservation, got {accepted.Length}.");
var reservation = accepted[0]!;
Console.WriteLine("PASS concurrent reservation admits exactly one identity");

try
{
    await store.ReserveAsync(username + "-other", email.ToUpperInvariant(), actor);
    throw new Exception("Case-insensitive email collision accepted.");
}
catch (InvalidOperationException)
{
    Console.WriteLine("PASS case-insensitive email reservation collision denied");
}
await keycloak.CreateDisabledAdminCandidateAsync(username, email, reservation.Id);
await store.MarkReconciliationRequiredAsync(reservation.Id);
var user = await keycloak.FindProvisionedUserAsync(username)
    ?? throw new Exception("Created candidate not found.");
if (user.Enabled || !string.Equals(user.Email, email, StringComparison.OrdinalIgnoreCase) ||
    user.Attributes is null ||
    !user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
    markers.Count != 1 || markers[0] != reservation.Id.ToString("D"))
    throw new Exception("Keycloak disabled identity ownership verification failed.");
if ((await keycloak.GetDirectOryvaRolesAsync(user.Id)).Count != 0 ||
    (await keycloak.GetEffectiveOryvaRolesAsync(user.Id)).Count != 0)
    throw new Exception("New admin candidate already has ORYVA roles.");
Console.WriteLine("PASS canonical Keycloak identity, ownership marker and empty roles");

await store.BindVerifiedSubjectAsync(reservation.Id, username, email, actor, user.Id);
try
{
    await store.MarkPreparedAsync(reservation.Id, Guid.NewGuid().ToString());
    throw new Exception("Wrong subject unexpectedly marked prepared.");
}
catch (InvalidOperationException)
{
    Console.WriteLine("PASS mismatched subject cannot mark prepared");
}
await store.MarkPreparedAsync(reservation.Id, user.Id);
await using var connection = await source.OpenConnectionAsync();
await using var command = new NpgsqlCommand(
    "SELECT state, keycloak_subject_id FROM oryva.admin_provisioning WHERE id = @id", connection);
command.Parameters.AddWithValue("id", reservation.Id);
await using var reader = await command.ExecuteReaderAsync();
if (!await reader.ReadAsync() || reader.GetString(0) != "prepared" ||
    reader.GetString(1) != user.Id)
    throw new Exception("Prepared reservation not persisted correctly.");
Console.WriteLine("PASS prepared state bound to verified Keycloak subject");

var lockManager = new AdminProvisioningLock(source);
var reconciler = new AdminProvisioningReconciler(store, keycloak, lockManager);
var inspected = await reconciler.InspectAsync(reservation.Id);
if (inspected is null || !inspected.IdentityVerified ||
    inspected.State != "prepared" ||
    inspected.Finding != "verified_disabled_candidate")
    throw new Exception("Prepared candidate inspection failed.");
Console.WriteLine("PASS read-only reconciliation verifies prepared candidate");

var missing = await reconciler.InspectAsync(Guid.NewGuid());
if (missing is not null)
    throw new Exception("Unknown provisioning reservation must not be adopted.");
Console.WriteLine("PASS unknown provisioning reservation is not adopted");

var recoveredPrepared = await reconciler.RecoverAsync(reservation.Id);
if (recoveredPrepared?.State != "prepared" || !recoveredPrepared.IdentityVerified)
    throw new Exception("Prepared recovery should be read-only and idempotent.");
Console.WriteLine("PASS prepared recovery is idempotent");

var recoveryUsername = "admin-recovery-" + Guid.NewGuid().ToString("N")[..12];
var recoveryEmail = recoveryUsername + "@example.invalid";
var pending = await store.ReserveAsync(recoveryUsername, recoveryEmail, actor);
await keycloak.CreateDisabledAdminCandidateAsync(recoveryUsername, recoveryEmail, pending.Id);
await store.MarkReconciliationRequiredAsync(pending.Id);
await using (var held = await lockManager.TryAcquireAsync(pending.Id)
    ?? throw new Exception("Could not acquire initial admin recovery lease."))
{
    await held.EnsureHeldAsync();
    await using var duplicate = await lockManager.TryAcquireAsync(pending.Id);
    if (duplicate is not null)
        throw new Exception("Second database session acquired the same admin lease.");
    await using var independent = await lockManager.TryAcquireAsync(Guid.NewGuid())
        ?? throw new Exception("Unrelated reservation should not be blocked.");

    var rejected = false;
    try { await reconciler.RecoverAsync(pending.Id); }
    catch (AdminProvisioningBusyException) { rejected = true; }
    if (!rejected)
        throw new Exception("Concurrent recovery must reject while lease is held.");
    var unchanged = await store.GetAsync(pending.Id);
    if (unchanged?.State != "reconciliation_required" ||
        unchanged.KeycloakSubjectId is not null)
        throw new Exception("Contended recovery mutated the reservation.");
    Console.WriteLine("PASS cross-session admin lease prevents concurrent recovery without mutation");
}
await using (var released = await lockManager.TryAcquireAsync(pending.Id)
    ?? throw new Exception("Admin recovery lease was not released."))
{
    await released.EnsureHeldAsync();
}
Console.WriteLine("PASS admin lease released and reacquirable");
var recovery = await reconciler.RecoverAsync(pending.Id);
if (recovery?.State != "prepared" || !recovery.IdentityVerified)
    throw new Exception("Interrupted Keycloak creation was not safely reconciled.");
Console.WriteLine("PASS interrupted creation recovered using verified ownership");

var unknownRecovery = await reconciler.RecoverAsync(Guid.NewGuid());
if (unknownRecovery is not null)
    throw new Exception("Unknown reservation was unexpectedly recovered.");
Console.WriteLine("PASS unknown reservation recovery denied");
