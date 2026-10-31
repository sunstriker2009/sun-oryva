using Npgsql;
using Sun.Security.Bootstrap;

var dsn = Environment.GetEnvironmentVariable("ORYVA_TEST_DATABASE_URL")
    ?? throw new InvalidOperationException("Missing test database URL.");
var secret = Environment.GetEnvironmentVariable("ORYVA_TEST_CLIENT_SECRET")
    ?? throw new InvalidOperationException("Missing test client secret.");
const string username = "e2e-master";
const string deployment = "e2e-isolated-deployment";
const string password = "E2e-Strong-Password-Only-2026!";
await using var dataSource = NpgsqlDataSource.Create(dsn);
var store = new MasterReservationStore(dataSource);
var provisioningLock = new MasterProvisioningLock(dataSource);
using var http = KeycloakHttpClientFactory.Create();
var keycloak = new KeycloakManagementClient(http, new KeycloakManagementOptions
{
    BaseAddress = new Uri("http://127.0.0.1:8080/"),
    ClientId = "oryva-e2e-bootstrap",
    ClientSecret = secret
});
var coordinator = new MasterProvisioningCoordinator(provisioningLock, store, keycloak);
var verifier = new MasterIdentityVerifier(store, keycloak, provisioningLock);

static async Task RejectAsync(Func<Task> operation, string scenario)
{
    try { await operation(); }
    catch (InvalidOperationException) { Console.WriteLine("PASS rejected: " + scenario); return; }
    throw new Exception("Expected rejection: " + scenario);
}
if (await store.GetActiveMasterSubjectAsync() is not null)
    throw new Exception("Fresh deployment already has active master.");
await coordinator.PrepareAsync(username, "master@example.invalid", deployment);
await coordinator.PrepareAsync(username, "master@example.invalid", deployment); // restart recovery
await RejectAsync(() => coordinator.EnablePreparedMasterAsync(username, deployment), "missing role/password");
await RejectAsync(() => coordinator.SetPreparedInitialPasswordAsync(username, "wrong-deployment", password), "ownership mismatch");
await coordinator.SetPreparedInitialPasswordAsync(username, deployment, password);
await coordinator.AssignPreparedMasterRoleAsync(username, deployment);
await coordinator.AssignPreparedMasterRoleAsync(username, deployment); // role retry
await RejectAsync(() => coordinator.EnablePreparedMasterAsync(username, "wrong-deployment"), "wrong enablement owner");
await coordinator.EnablePreparedMasterAsync(username, deployment);
await coordinator.EnablePreparedMasterAsync(username, deployment); // ambiguous response reconciliation
if (await store.GetActiveMasterSubjectAsync() is not null)
    throw new Exception("Enabled Keycloak identity must not imply database activation.");
await RejectAsync(() => verifier.VerifyAndActivateAsync(username, "wrong-deployment"), "wrong activation owner");
var active = await verifier.VerifyAndActivateAsync(username, deployment);
if (!active.IsActive || string.IsNullOrWhiteSpace(active.SubjectId))
    throw new Exception("Activation failed.");
var repeated = await verifier.VerifyAndActivateAsync(username, deployment);
if (repeated.SubjectId != active.SubjectId ||
    await store.GetActiveMasterSubjectAsync() != active.SubjectId)
    throw new Exception("Idempotent activation or runtime binding failed.");
await RejectAsync(() => coordinator.PrepareAsync("another-master", "other@example.invalid", deployment), "second master");
await RejectAsync(() => coordinator.SetPreparedInitialPasswordAsync(username, deployment, password), "password reset after activation");
await RejectAsync(() => coordinator.EnablePreparedMasterAsync(username, deployment), "enable after activation");
Console.WriteLine("PASS full .NET/Keycloak/PostgreSQL master bootstrap and recovery");
