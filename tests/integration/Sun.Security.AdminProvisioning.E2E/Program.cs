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
