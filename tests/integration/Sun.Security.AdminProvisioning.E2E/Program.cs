using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Sun.Security.AspNetCore;
using System.Net.Http.Json;
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
var firstAudit = await store.GetAuditAsync(reservation.Id);
var expectedEvents = new[] { "reserved", "reconciliation_required", "subject_bound", "prepared" };
if (!firstAudit.Select(x => x.EventType).SequenceEqual(expectedEvents) ||
    firstAudit.Any(x => x.ActorSubject != actor) ||
    firstAudit.Zip(firstAudit.Skip(1)).Any(pair => pair.First.EventId >= pair.Second.EventId))
    throw new Exception("Provisioning audit must contain the ordered, actor-bound transitions.");
Console.WriteLine("PASS atomic, ordered audit events for prepared admin candidate");

await using (var auditConnection = await source.OpenConnectionAsync())
await using (var mutation = new NpgsqlCommand(
    "UPDATE oryva.admin_provisioning_audit SET event_type = 'reserved' WHERE provisioning_id = @id",
    auditConnection))
{
    mutation.Parameters.AddWithValue("id", reservation.Id);
    var blocked = false;
    try { await mutation.ExecuteNonQueryAsync(); }
    catch (PostgresException ex) when (ex.SqlState == "P0001") { blocked = true; }
    if (!blocked)
        throw new Exception("Audit mutation must be rejected by the database.");
}
Console.WriteLine("PASS PostgreSQL rejects updates to append-only audit records");
await using (var auditConnection = await source.OpenConnectionAsync())
await using (var truncate = new NpgsqlCommand(
    "TRUNCATE TABLE oryva.admin_provisioning_audit", auditConnection))
{
    var blocked = false;
    try { await truncate.ExecuteNonQueryAsync(); }
    catch (PostgresException ex) when (ex.SqlState == "P0001") { blocked = true; }
    if (!blocked)
        throw new Exception("Audit truncation must be rejected by the database.");
}
Console.WriteLine("PASS PostgreSQL rejects truncation of audit history");



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
var recoveredAudit = await store.GetAuditAsync(pending.Id);
if (!recoveredAudit.Select(x => x.EventType).SequenceEqual(expectedEvents))
    throw new Exception("Recovery must audit subject binding and prepared transition.");
Console.WriteLine("PASS interrupted recovery produces complete audit history");


var unknownRecovery = await reconciler.RecoverAsync(Guid.NewGuid());
if (unknownRecovery is not null)
    throw new Exception("Unknown reservation was unexpectedly recovered.");
Console.WriteLine("PASS unknown reservation recovery denied");

var roleCoordinator = new AdminRoleAssignmentCoordinator(store, keycloak, lockManager);
await using (var held = await lockManager.TryAcquireAsync(pending.Id)
    ?? throw new Exception("Could not hold admin role assignment lease."))
{
    var rejected = false;
    try { await roleCoordinator.AssignAsync(pending.Id); }
    catch (AdminProvisioningBusyException) { rejected = true; }
    if (!rejected)
        throw new Exception("Concurrent admin role assignment must reject.");
    if ((await store.GetAsync(pending.Id))?.State != "prepared")
        throw new Exception("Contended role assignment mutated reservation.");
}
Console.WriteLine("PASS cross-instance lock blocks concurrent role assignment");

var assigned = await roleCoordinator.AssignAsync(pending.Id);
if (assigned?.State != "role_assigned" || !assigned.Transitioned)
    throw new Exception("Admin role was not assigned and verified.");
var assignedUser = await keycloak.FindProvisionedUserAsync(recoveryUsername)
    ?? throw new Exception("Assigned Keycloak candidate disappeared.");
if (assignedUser.Enabled ||
    await keycloak.HasPasswordCredentialAsync(assignedUser.Id) ||
    !(await keycloak.GetDirectOryvaRolesAsync(assignedUser.Id)).SequenceEqual(["admin"]) ||
    !(await keycloak.GetEffectiveOryvaRolesAsync(assignedUser.Id)).SequenceEqual(["admin"]))
    throw new Exception("Admin role must be exclusive and identity disabled/uncredentialed.");
Console.WriteLine("PASS exclusive admin role assigned to disabled, uncredentialed identity");

var repeatAssignment = await roleCoordinator.AssignAsync(pending.Id);
if (repeatAssignment?.State != "role_assigned" || repeatAssignment.Transitioned)
    throw new Exception("Verified admin role assignment should be idempotent.");
var roleAudit = await store.GetAuditAsync(pending.Id);
if (!roleAudit.Select(x => x.EventType).SequenceEqual(
    ["reserved", "reconciliation_required", "subject_bound", "prepared",
     "role_assignment_pending", "role_assigned"]))
    throw new Exception("Role assignment audit must be complete and append-only.");
var assignedInspection = await reconciler.InspectAsync(pending.Id);
if (assignedInspection?.Finding != "verified_disabled_admin" ||
    !assignedInspection.IdentityVerified)
    throw new Exception("Inspection must recognize a disabled role-assigned admin.");
Console.WriteLine("PASS idempotent role reconciliation and audited transitions");

var missingRoleAssignment = await roleCoordinator.AssignAsync(Guid.NewGuid());
if (missingRoleAssignment is not null)
    throw new Exception("Unknown reservation must not receive an admin role.");
var unprepared = await store.ReserveAsync(
    "admin-unprepared-" + Guid.NewGuid().ToString("N")[..12],
    Guid.NewGuid().ToString("N") + "@example.invalid", actor);
var deniedUnprepared = false;
try { await roleCoordinator.AssignAsync(unprepared.Id); }
catch (InvalidOperationException) { deniedUnprepared = true; }
if (!deniedUnprepared || (await store.GetAsync(unprepared.Id))?.State != "reserved")
    throw new Exception("Unprepared admin reservation must not be promoted.");
Console.WriteLine("PASS missing and unprepared reservations cannot be promoted");

// Simulate an out-of-band role mapping before the durable pending marker.
// The coordinator must refuse to adopt this privilege as its own action.
await keycloak.AddAdminRoleMappingAsync(user.Id);
var deniedExternal = false;
try { await roleCoordinator.AssignAsync(reservation.Id); }
catch (InvalidOperationException) { deniedExternal = true; }
if (!deniedExternal || (await store.GetAsync(reservation.Id))?.State != "prepared")
    throw new Exception("Unexpected external role assignment must fail closed.");
Console.WriteLine("PASS unexpected pre-existing admin role is not adopted");

var ambiguousUsername = "admin-ambiguous-" + Guid.NewGuid().ToString("N")[..12];
var ambiguousEmail = ambiguousUsername + "@example.invalid";
var ambiguous = await store.ReserveAsync(ambiguousUsername, ambiguousEmail, actor);
await keycloak.CreateDisabledAdminCandidateAsync(ambiguousUsername, ambiguousEmail, ambiguous.Id);
await store.MarkReconciliationRequiredAsync(ambiguous.Id);
var ambiguousUser = await keycloak.FindProvisionedUserAsync(ambiguousUsername)
    ?? throw new Exception("Missing ambiguous role candidate.");
await store.BindVerifiedSubjectAsync(
    ambiguous.Id, ambiguousUsername, ambiguousEmail, actor, ambiguousUser.Id);
await store.MarkPreparedAsync(ambiguous.Id, ambiguousUser.Id);
// Simulate a lost Keycloak response after durable intent and successful mapping.
await store.MarkRoleAssignmentPendingAsync(ambiguous.Id, ambiguousUser.Id);
await keycloak.AddAdminRoleMappingAsync(ambiguousUser.Id);
var reconciledRole = await roleCoordinator.AssignAsync(ambiguous.Id);
if (reconciledRole?.State != "role_assigned" || !reconciledRole.Transitioned ||
    (await keycloak.FindProvisionedUserAsync(ambiguousUsername))?.Enabled != false)
    throw new Exception("Ambiguous role mapping response was not reconciled safely.");
Console.WriteLine("PASS lost role assignment response reconciled without activation");

var passwordUsername = "admin-credentialed-" + Guid.NewGuid().ToString("N")[..12];
var passwordEmail = passwordUsername + "@example.invalid";
var credentialed = await store.ReserveAsync(passwordUsername, passwordEmail, actor);
await keycloak.CreateDisabledAdminCandidateAsync(passwordUsername, passwordEmail, credentialed.Id);
await store.MarkReconciliationRequiredAsync(credentialed.Id);
var credentialedUser = await keycloak.FindProvisionedUserAsync(passwordUsername)
    ?? throw new Exception("Missing credentialed candidate.");
await store.BindVerifiedSubjectAsync(
    credentialed.Id, passwordUsername, passwordEmail, actor, credentialedUser.Id);
await store.MarkPreparedAsync(credentialed.Id, credentialedUser.Id);
await keycloak.SetInitialPasswordAsync(credentialedUser.Id, "CI-Only-Password-2026!");
var credentialDenied = false;
try { await roleCoordinator.AssignAsync(credentialed.Id); }
catch (InvalidOperationException) { credentialDenied = true; }
if (!credentialDenied || (await store.GetAsync(credentialed.Id))?.State != "prepared")
    throw new Exception("Pre-credentialed candidate must not be promoted.");
Console.WriteLine("PASS credentialed admin candidate is rejected before role assignment");

var activationReadiness = new AdminActivationReadiness(store, keycloak, lockManager);
var uncredentialedReadiness = await activationReadiness.CheckAsync(pending.Id);
if (uncredentialedReadiness is null || uncredentialedReadiness.Ready ||
    uncredentialedReadiness.Finding != "password_missing")
    throw new Exception("Uncredentialed, role-assigned admin must not be activation-ready.");
Console.WriteLine("PASS real Keycloak uncredentialed admin cannot pass activation preflight");

await using (var held = await lockManager.TryAcquireAsync(pending.Id)
    ?? throw new Exception("Could not hold activation preflight lease."))
{
    var blocked = false;
    try { await activationReadiness.CheckAsync(pending.Id); }
    catch (AdminProvisioningBusyException) { blocked = true; }
    if (!blocked)
        throw new Exception("Activation preflight must not race a provisioning writer.");
}
Console.WriteLine("PASS activation preflight honors cross-instance provisioning lock");

var assignedState = await store.GetAsync(pending.Id)
    ?? throw new Exception("Assigned reservation disappeared.");
var syntheticVerified = assignedUser with
{
    EmailVerified = true,
    RequiredActions = new List<string>()
};
var ready = AdminActivationReadinessRules.Evaluate(
    assignedState, syntheticVerified, ["admin"], ["admin"], true);
if (!ready.Ready || ready.Finding != "ready_for_guarded_activation")
    throw new Exception("Fully verified synthetic candidate should pass readiness rules.");
var unverifiedEmail = AdminActivationReadinessRules.Evaluate(
    assignedState, syntheticVerified with { EmailVerified = false },
    ["admin"], ["admin"], true);
var pendingActions = AdminActivationReadinessRules.Evaluate(
    assignedState, syntheticVerified with { RequiredActions = ["UPDATE_PASSWORD"] },
    ["admin"], ["admin"], true);
var missingActionsMetadata = AdminActivationReadinessRules.Evaluate(
    assignedState, syntheticVerified with { RequiredActions = null },
    ["admin"], ["admin"], true);
var inheritedViewer = AdminActivationReadinessRules.Evaluate(
    assignedState, syntheticVerified, ["admin"], ["admin", "viewer"], true);
var enabledEarly = AdminActivationReadinessRules.Evaluate(
    assignedState, syntheticVerified with { Enabled = true },
    ["admin"], ["admin"], true);
var mismatchedOwner = AdminActivationReadinessRules.Evaluate(
    assignedState, syntheticVerified with { Attributes = new Dictionary<string, List<string>>() },
    ["admin"], ["admin"], true);
if (unverifiedEmail.Ready || unverifiedEmail.Finding != "email_not_verified" ||
    pendingActions.Ready || pendingActions.Finding != "required_actions_pending" ||
    missingActionsMetadata.Ready || missingActionsMetadata.Finding != "required_actions_pending" ||
    inheritedViewer.Ready || inheritedViewer.Finding != "role_mismatch" ||
    enabledEarly.Ready || enabledEarly.Finding != "identity_mismatch" ||
    mismatchedOwner.Ready || mismatchedOwner.Finding != "identity_mismatch")
    throw new Exception("Activation readiness rules must fail closed on every mismatch.");
Console.WriteLine("PASS activation readiness requires verified email, completed actions, exclusive role and ownership");

if (await activationReadiness.CheckAsync(Guid.NewGuid()) is not null)
    throw new Exception("Unknown reservation must not pass activation readiness.");
if ((await activationReadiness.CheckAsync(unprepared.Id))?.Finding != "role_not_assigned")
    throw new Exception("Unprepared reservation must not pass activation readiness.");
Console.WriteLine("PASS missing and unprepared reservations cannot pass activation preflight");

var activator = new AdminActivationCoordinator(store, keycloak, lockManager);
var refusedUncredentialed = false;
try { await activator.ActivateAsync(pending.Id); }
catch (InvalidOperationException) { refusedUncredentialed = true; }
if (!refusedUncredentialed || (await store.GetAsync(pending.Id))?.State != "role_assigned" ||
    (await keycloak.FindProvisionedUserAsync(recoveryUsername))?.Enabled != false)
    throw new Exception("Uncredentialed admin must not be enabled or transition state.");
Console.WriteLine("PASS uncredentialed admin activation fails closed");

var activateName = "admin-activation-" + Guid.NewGuid().ToString("N")[..12];
var activateEmail = activateName + "@example.invalid";
var activateReservation = await store.ReserveAsync(activateName, activateEmail, actor);
await keycloak.CreateDisabledAdminCandidateAsync(activateName, activateEmail, activateReservation.Id);
await store.MarkReconciliationRequiredAsync(activateReservation.Id);
var activateUser = await keycloak.FindProvisionedUserAsync(activateName)
    ?? throw new Exception("Missing activation test candidate.");
await store.BindVerifiedSubjectAsync(
    activateReservation.Id, activateName, activateEmail, actor, activateUser.Id);
await store.MarkPreparedAsync(activateReservation.Id, activateUser.Id);
if ((await roleCoordinator.AssignAsync(activateReservation.Id))?.State != "role_assigned")
    throw new Exception("Activation fixture role assignment failed.");
await keycloak.SetInitialPasswordAsync(activateUser.Id, "CI-Only-Activation-2026!");
await VerifyTestEmailAsync(activateUser.Id, activateName, activateEmail, activateReservation.Id);
if ((await activationReadiness.CheckAsync(activateReservation.Id))?.Ready != true)
    throw new Exception("Verified CI candidate must pass real Keycloak activation readiness.");
await using (var held = await lockManager.TryAcquireAsync(activateReservation.Id)
    ?? throw new Exception("Could not hold activation lease."))
{
    var blocked = false;
    try { await activator.ActivateAsync(activateReservation.Id); }
    catch (AdminProvisioningBusyException) { blocked = true; }
    if (!blocked || (await store.GetAsync(activateReservation.Id))?.State != "role_assigned")
        throw new Exception("Concurrent activation must not mutate state.");
}
var activated = await activator.ActivateAsync(activateReservation.Id);
if (activated?.State != "active" || !activated.Transitioned ||
    (await keycloak.FindProvisionedUserAsync(activateName))?.Enabled != true)
    throw new Exception("Verified admin activation failed.");
var repeatActivation = await activator.ActivateAsync(activateReservation.Id);
if (repeatActivation?.Transitioned != false || repeatActivation.State != "active")
    throw new Exception("Verified active admin should be idempotent.");
var activationEvents = await store.GetAuditAsync(activateReservation.Id);
if (!activationEvents.Select(e => e.EventType).TakeLast(2)
    .SequenceEqual(["activation_pending", "active"]))
    throw new Exception("Activation intent and confirmation must be audited.");
Console.WriteLine("PASS verified activation, exclusive role, lease, idempotence and audit");

// Database state, not a valid admin realm role alone, authorizes API operations.
var activeAdmins = new ActiveAdminAuthorization(store);
if (!await activeAdmins.IsActiveAdminSubjectAsync(activateUser.Id, true) ||
    await activeAdmins.IsActiveAdminSubjectAsync(activateUser.Id, false) ||
    await activeAdmins.IsActiveAdminSubjectAsync(assignedUser.Id, true) ||
    await activeAdmins.IsActiveAdminSubjectAsync("unknown-subject", true) ||
    await activeAdmins.IsActiveAdminSubjectAsync(null, true))
    throw new Exception("Active-admin database gate accepted an inactive or invalid identity.");
Console.WriteLine("PASS active-admin database authorization accepts only committed active subject");

var webBuilder = WebApplication.CreateBuilder(
    new WebApplicationOptions { EnvironmentName = "Development" });
webBuilder.WebHost.UseTestServer();
webBuilder.Services.AddSingleton(source);
webBuilder.Services.AddScoped<AdminProvisioningStore>();
webBuilder.Services.AddAuthentication("E2EAdmin")
    .AddScheme<AuthenticationSchemeOptions, E2EAdminAuthHandler>("E2EAdmin", _ => { });
webBuilder.Services.AddOryvaRolePolicies();
await using (var webApp = webBuilder.Build())
{
    webApp.UseAuthentication();
    webApp.UseAuthorization();
    webApp.MapGet("/test/admin", () => Microsoft.AspNetCore.Http.Results.Ok())
        .RequireAuthorization(OryvaRolePolicyExtensions.Admin);
    webApp.MapGet("/test/viewer", () => Microsoft.AspNetCore.Http.Results.Ok())
        .RequireAuthorization(OryvaRolePolicyExtensions.Viewer);
    await webApp.StartAsync();
    using var client = webApp.GetTestClient();
    async Task CheckAsync(string route, string? subject, string? role,
        System.Net.HttpStatusCode expected)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, route);
        if (subject is not null) request.Headers.Add("X-E2E-Subject", subject);
        if (role is not null) request.Headers.Add("X-E2E-Role", role);
        using var response = await client.SendAsync(request);
        if (response.StatusCode != expected)
            throw new Exception($"HTTP {route} subject={subject} role={role} expected {(int)expected}, got {(int)response.StatusCode}");
    }
    await CheckAsync("/test/admin", null, null, System.Net.HttpStatusCode.Unauthorized);
    await CheckAsync("/test/admin", activateUser.Id, "viewer", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/admin", activateUser.Id, "master", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/admin", assignedUser.Id, "admin", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/viewer", assignedUser.Id, "admin", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/admin", "unknown-subject", "admin", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/admin", activateUser.Id, "admin", System.Net.HttpStatusCode.OK);
    await CheckAsync("/test/viewer", activateUser.Id, "admin", System.Net.HttpStatusCode.OK);
    await CheckAsync("/test/viewer", assignedUser.Id, "viewer", System.Net.HttpStatusCode.OK);
    await CheckAsync("/test/viewer", activateUser.Id, "master", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/admin", activateUser.Id, "admin,viewer", System.Net.HttpStatusCode.Forbidden);
    Console.WriteLine("PASS HTTP admin/viewer policies enforce active DB state, exclusive role, 401/403/200");
    await webApp.StopAsync();
}

// Deactivation must deny previously issued admin JWTs before Keycloak I/O.
var deactivator = new AdminDeactivationCoordinator(store, keycloak, lockManager);
if (await deactivator.DeactivateAsync(Guid.NewGuid(), actor) is not null)
    throw new Exception("Unknown admin reservation unexpectedly deactivated.");
var invalidDeactivation = false;
try { await deactivator.DeactivateAsync(pending.Id, actor); }
catch (InvalidOperationException) { invalidDeactivation = true; }
if (!invalidDeactivation)
    throw new Exception("Non-active candidate must not be deactivated.");
await using (var held = await lockManager.TryAcquireAsync(activateReservation.Id)
    ?? throw new Exception("Could not acquire deactivation contention lease."))
{
    var blocked = false;
    try { await deactivator.DeactivateAsync(activateReservation.Id, actor); }
    catch (AdminProvisioningBusyException) { blocked = true; }
    if (!blocked || !await activeAdmins.IsActiveAdminSubjectAsync(activateUser.Id, true))
        throw new Exception("Contended deactivation must not change active state.");
}
var deactivated = await deactivator.DeactivateAsync(activateReservation.Id, actor);
if (deactivated?.State != "deactivated" || !deactivated.Transitioned ||
    await activeAdmins.IsActiveAdminSubjectAsync(activateUser.Id, true) ||
    (await keycloak.FindProvisionedUserAsync(activateName))?.Enabled != false)
    throw new Exception("Admin deactivation did not revoke database and Keycloak access.");
var repeatDeactivation = await deactivator.DeactivateAsync(activateReservation.Id, actor);
if (repeatDeactivation?.Transitioned != false || repeatDeactivation.State != "deactivated")
    throw new Exception("Admin deactivation retry should be idempotent.");
var deactivationEvents = (await store.GetAuditAsync(activateReservation.Id)).TakeLast(2).ToArray();
if (!deactivationEvents.Select(e => e.EventType)
        .SequenceEqual(["deactivation_pending", "deactivated"]) ||
    deactivationEvents.Any(e => e.ActorSubject != actor))
    throw new Exception("Revocation transitions must be audited with master actor.");
Console.WriteLine("PASS admin deactivation, logout, runtime denial, lock contention, idempotence and audit");

// Simulate Keycloak enabling a verified candidate while the HTTP response is lost.
// A retry must adopt only a previously persisted activation_pending intent.
var ambiguousActivationName = "admin-enable-retry-" + Guid.NewGuid().ToString("N")[..12];
var ambiguousActivationEmail = ambiguousActivationName + "@example.invalid";
var ambiguousActivation = await store.ReserveAsync(
    ambiguousActivationName, ambiguousActivationEmail, actor);
await keycloak.CreateDisabledAdminCandidateAsync(
    ambiguousActivationName, ambiguousActivationEmail, ambiguousActivation.Id);
await store.MarkReconciliationRequiredAsync(ambiguousActivation.Id);
var ambiguousActivationUser = await keycloak.FindProvisionedUserAsync(ambiguousActivationName)
    ?? throw new Exception("Missing ambiguous activation candidate.");
await store.BindVerifiedSubjectAsync(ambiguousActivation.Id, ambiguousActivationName,
    ambiguousActivationEmail, actor, ambiguousActivationUser.Id);
await store.MarkPreparedAsync(ambiguousActivation.Id, ambiguousActivationUser.Id);
await roleCoordinator.AssignAsync(ambiguousActivation.Id);
await keycloak.SetInitialPasswordAsync(ambiguousActivationUser.Id, "CI-Only-Recovery-2026!");
await VerifyTestEmailAsync(ambiguousActivationUser.Id, ambiguousActivationName,
    ambiguousActivationEmail, ambiguousActivation.Id);
await store.MarkActivationPendingAsync(ambiguousActivation.Id, ambiguousActivationUser.Id);
await keycloak.EnableUserAsync(ambiguousActivationUser.Id);
var recoveredActivation = await activator.ActivateAsync(ambiguousActivation.Id);
if (recoveredActivation?.State != "active" || !recoveredActivation.Transitioned)
    throw new Exception("Ambiguous enable response was not reconciled.");
Console.WriteLine("PASS ambiguous Keycloak enable response reconciles only durable intent");
await store.MarkDeactivationPendingAsync(ambiguousActivation.Id, ambiguousActivationUser.Id, actor);
if (await activeAdmins.IsActiveAdminSubjectAsync(ambiguousActivationUser.Id, true) ||
    (await keycloak.FindProvisionedUserAsync(ambiguousActivationName))?.Enabled != true)
    throw new Exception("Durable revocation intent must immediately deny an enabled Keycloak admin.");
var recoveredDeactivation = await deactivator.DeactivateAsync(ambiguousActivation.Id, actor);
if (recoveredDeactivation?.State != "deactivated" || !recoveredDeactivation.Transitioned ||
    (await keycloak.FindProvisionedUserAsync(ambiguousActivationName))?.Enabled != false ||
    await activeAdmins.IsActiveAdminSubjectAsync(ambiguousActivationUser.Id, true))
    throw new Exception("Interrupted admin deactivation did not reconcile.");
Console.WriteLine("PASS pending deactivation denies access before Keycloak disable and recovers safely");

static async Task VerifyTestEmailAsync(
    string subject, string username, string email, Guid reservationId)
{
    // Isolated CI fixture only: production APIs must never mark email verified.
    var admin = Environment.GetEnvironmentVariable("ORYVA_TEST_KEYCLOAK_ADMIN")
        ?? throw new InvalidOperationException("Missing CI Keycloak administrator.");
    var password = Environment.GetEnvironmentVariable("ORYVA_TEST_KEYCLOAK_PASSWORD")
        ?? throw new InvalidOperationException("Missing CI Keycloak password.");
    using var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
    using var tokenResponse = await client.PostAsync(
        "http://127.0.0.1:8080/realms/master/protocol/openid-connect/token",
        new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["client_id"] = "admin-cli",
            ["username"] = admin,
            ["password"] = password
        }));
    tokenResponse.EnsureSuccessStatusCode();
    var tokenJson = await tokenResponse.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>();
    var token = tokenJson.GetProperty("access_token").GetString()
        ?? throw new Exception("CI admin token missing.");
    using var update = new HttpRequestMessage(HttpMethod.Put,
        "http://127.0.0.1:8080/admin/realms/oryva/users/" + Uri.EscapeDataString(subject));
    update.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
        "Bearer", token);
    update.Content = System.Net.Http.Json.JsonContent.Create(new
    {
        username, email, enabled = false, emailVerified = true,
        requiredActions = Array.Empty<string>(),
        attributes = new Dictionary<string, string[]>
        {
            ["oryva.provisioning.id"] = [reservationId.ToString("D")]
        }
    });
    using var response = await client.SendAsync(update);
    response.EnsureSuccessStatusCode();
}

sealed class E2EAdminAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-E2E-Subject", out var subject))
            return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new List<Claim> { new("sub", subject.ToString()) };
        if (Request.Headers.TryGetValue("X-E2E-Role", out var role))
        {
            foreach (var value in role.ToString().Split(','))
                claims.Add(new Claim("oryva_realm_role", value));
        }
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(
                new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name)), Scheme.Name)));
    }
}
