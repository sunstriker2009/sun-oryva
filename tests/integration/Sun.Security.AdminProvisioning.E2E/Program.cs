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
webBuilder.Services.AddScoped<MasterReservationStore>();
webBuilder.Services.AddAuthentication("E2EAdmin")
    .AddScheme<AuthenticationSchemeOptions, E2EAdminAuthHandler>("E2EAdmin", _ => { });
webBuilder.Services.AddOryvaRolePolicies();
webBuilder.Services.AddOryvaActiveMasterPolicy();
await using (var webApp = webBuilder.Build())
{
    webApp.UseAuthentication();
    webApp.UseAuthorization();
    webApp.MapGet("/test/admin", () => Microsoft.AspNetCore.Http.Results.Ok())
        .RequireAuthorization(OryvaRolePolicyExtensions.Admin);
    webApp.MapGet("/test/viewer", () => Microsoft.AspNetCore.Http.Results.Ok())
        .RequireAuthorization(OryvaRolePolicyExtensions.Viewer);
    webApp.MapGet("/test/manage-viewer", async (
        Microsoft.AspNetCore.Authorization.IAuthorizationService authorization,
        ClaimsPrincipal principal) =>
    {
        var role = await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal);
        return role is null ? Microsoft.AspNetCore.Http.Results.Forbid() :
            Microsoft.AspNetCore.Http.Results.Ok();
    }).RequireAuthorization();
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
    await CheckAsync("/test/viewer", assignedUser.Id, "viewer", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/viewer", activateUser.Id, "master", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/admin", activateUser.Id, "admin,viewer", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/manage-viewer", null, null, System.Net.HttpStatusCode.Unauthorized);
    await CheckAsync("/test/manage-viewer", activateUser.Id, "admin", System.Net.HttpStatusCode.OK);
    await CheckAsync("/test/manage-viewer", assignedUser.Id, "admin", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/manage-viewer", activateUser.Id, "viewer", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/manage-viewer", activateUser.Id, "admin,viewer", System.Net.HttpStatusCode.Forbidden);
    await CheckAsync("/test/manage-viewer", activateUser.Id, "master,admin", System.Net.HttpStatusCode.Forbidden);
    Console.WriteLine("PASS viewer manager HTTP gate requires active admin and exclusive role");
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

// M5: viewer preparation is intentionally disabled/unprivileged and recoverable.
var viewerStore = new ViewerAccountStore(source);
var viewerLock = new ViewerProvisioningLock(source);
var viewerCoordinator = new ViewerPreparationCoordinator(viewerStore, keycloak, viewerLock);
var viewerRoleCoordinator = new ViewerRoleAssignmentCoordinator(viewerStore, keycloak, viewerLock);
var viewerName = "viewer-candidate-" + Guid.NewGuid().ToString("N")[..12];
var viewerEmail = viewerName + "@example.invalid";
var viewerReservations = await Task.WhenAll(
    Enumerable.Range(0, 8).Select(async _ =>
    {
        try { return await viewerStore.ReserveAsync(viewerName, viewerEmail, actor, "master"); }
        catch (ViewerReservationConflictException) { return null; }
    }));
var viewerAccepted = viewerReservations.Where(x => x is not null).ToArray();
if (viewerAccepted.Length != 1)
    throw new Exception("Viewer reservation must admit only one concurrent identity.");
var viewerReservation = viewerAccepted[0]!;
try
{
    await viewerStore.ReserveAsync(viewerName + "-other", viewerEmail.ToUpperInvariant(), actor, "admin");
    throw new Exception("Case-insensitive duplicate viewer email accepted.");
}
catch (ViewerReservationConflictException) { }
Console.WriteLine("PASS viewer reservation uniqueness and case-insensitive email conflicts");

var initialViewerAudit = await viewerStore.GetAuditAsync(viewerReservation.Id);
if (initialViewerAudit.Count != 1 ||
    initialViewerAudit[0].EventType != "reserved" ||
    initialViewerAudit[0].ActorSubject != actor ||
    initialViewerAudit[0].ActorRole != "master")
    throw new Exception("Viewer reservation must atomically append exactly one actor-bound audit event.");
if ((await viewerStore.GetAuditAsync(Guid.NewGuid())).Count != 0)
    throw new Exception("Unknown viewer must have no audit events.");
Console.WriteLine("PASS concurrent viewer reservation writes exactly one append-only actor audit");


await keycloak.CreateDisabledViewerCandidateAsync(viewerName, viewerEmail, viewerReservation.Id);
var viewerPrepared = await viewerCoordinator.RecoverAsync(viewerReservation.Id, actor, "admin");
if (viewerPrepared?.State != "prepared" ||
    string.IsNullOrWhiteSpace(viewerPrepared.KeycloakSubjectId) ||
    await viewerStore.IsActiveViewerSubjectAsync(viewerPrepared.KeycloakSubjectId))
    throw new Exception("Viewer preparation granted access or did not bind the subject.");
var viewerKeycloak = await keycloak.FindProvisionedUserAsync(viewerName)
    ?? throw new Exception("Viewer candidate missing.");
if (viewerKeycloak.Enabled || viewerKeycloak.EmailVerified ||
    await keycloak.HasPasswordCredentialAsync(viewerKeycloak.Id) ||
    (await keycloak.GetDirectOryvaRolesAsync(viewerKeycloak.Id)).Count != 0 ||
    (await keycloak.GetEffectiveOryvaRolesAsync(viewerKeycloak.Id)).Count != 0)
    throw new Exception("Viewer preparation unexpectedly granted credentials or privileges.");
if ((await viewerCoordinator.RecoverAsync(viewerReservation.Id, actor, "master"))?.State != "prepared")
    throw new Exception("Viewer recovery should be idempotent.");
var preparedViewerEvents = await viewerStore.GetAuditAsync(viewerReservation.Id);
if (!preparedViewerEvents.Select(x => x.EventType).SequenceEqual(["reserved", "prepared"]) ||
    preparedViewerEvents[0].ActorRole != "master" ||
    preparedViewerEvents[1].ActorRole != "admin" ||
    preparedViewerEvents.Any(x => x.ActorSubject != actor) ||
    preparedViewerEvents[0].EventId >= preparedViewerEvents[1].EventId)
    throw new Exception("Preparation audit must attribute the actual recovering actor exactly once.");
var rejectedPreparedActor = false;
try { await viewerStore.MarkPreparedAsync(viewerReservation.Id, viewerKeycloak.Id, actor, "viewer"); }
catch (ArgumentException) { rejectedPreparedActor = true; }
if (!rejectedPreparedActor || (await viewerStore.GetAuditAsync(viewerReservation.Id)).Count != 2)
    throw new Exception("Viewer actor cannot write a preparation event.");
Console.WriteLine("PASS real Keycloak viewer preparation, atomic audit and idempotent recovery");

// M5: guarded viewer role assignment never enables or credentials the account.
if (await viewerRoleCoordinator.AssignAsync(Guid.NewGuid(), actor, "master") is not null)
    throw new Exception("Unknown viewer reservation should not assign a role.");
var wrongActorRoleRejected = false;
try { await viewerRoleCoordinator.AssignAsync(viewerReservation.Id, actor, "viewer"); }
catch (ArgumentException) { wrongActorRoleRejected = true; }
if (!wrongActorRoleRejected)
    throw new Exception("Viewer actors must not assign viewer roles.");

await using (var held = await viewerLock.TryAcquireAsync(viewerReservation.Id)
    ?? throw new Exception("Could not hold viewer provisioning lease."))
{
    var blocked = false;
    try { await viewerRoleCoordinator.AssignAsync(viewerReservation.Id, actor, "master"); }
    catch (ViewerProvisioningBusyException) { blocked = true; }
    if (!blocked || (await viewerStore.GetAsync(viewerReservation.Id))?.State != "prepared")
        throw new Exception("Contended viewer role assignment mutated state.");
}
var viewerAssigned = await viewerRoleCoordinator.AssignAsync(viewerReservation.Id, actor, "master");
if (viewerAssigned?.State != "role_assigned" || !viewerAssigned.Transitioned ||
    (await viewerStore.GetAsync(viewerReservation.Id))?.State != "role_assigned" ||
    await viewerStore.IsActiveViewerSubjectAsync(viewerKeycloak.Id) ||
    (await keycloak.FindProvisionedUserAsync(viewerName))?.Enabled != false ||
    await keycloak.HasPasswordCredentialAsync(viewerKeycloak.Id) ||
    !(await keycloak.GetDirectOryvaRolesAsync(viewerKeycloak.Id)).SequenceEqual(["viewer"]) ||
    !(await keycloak.GetEffectiveOryvaRolesAsync(viewerKeycloak.Id)).SequenceEqual(["viewer"]))
    throw new Exception("Viewer role assignment must be exclusive, disabled and non-authorizing.");
if ((await viewerRoleCoordinator.AssignAsync(viewerReservation.Id, actor, "admin"))?.Transitioned != false)
    throw new Exception("Verified viewer role assignment should be idempotent.");
var viewerEvents = await viewerStore.GetAuditAsync(viewerReservation.Id);
if (!viewerEvents.Select(x => x.EventType)
        .SequenceEqual(["reserved", "prepared", "role_assignment_pending", "role_assigned"]) ||
    viewerEvents.Any(x => x.ActorSubject != actor) ||
    viewerEvents[0].ActorRole != "master" || viewerEvents[1].ActorRole != "admin" ||
    viewerEvents.Skip(2).Any(x => x.ActorRole != "master") ||
    viewerEvents.Zip(viewerEvents.Skip(1)).Any(x => x.First.EventId >= x.Second.EventId))
    throw new Exception("Viewer role audit must be ordered and actor-bound.");
Console.WriteLine("PASS viewer role assignment, advisory contention, idempotence, disabled state and audit");

// Readiness is read-only: never enable a viewer from this preflight.
var viewerReadiness = new ViewerActivationReadiness(viewerStore, keycloak, viewerLock);
if (await viewerReadiness.CheckAsync(Guid.NewGuid()) is not null)
    throw new Exception("Unknown viewer readiness reservation must not be adopted.");
var viewerBeforeEnrollment = await viewerReadiness.CheckAsync(viewerReservation.Id);
if (viewerBeforeEnrollment?.Ready != false ||
    viewerBeforeEnrollment.Finding != "password_missing" ||
    await viewerStore.IsActiveViewerSubjectAsync(viewerKeycloak.Id))
    throw new Exception("Uncredentialed viewer incorrectly passed readiness.");
Console.WriteLine("PASS uncredentialed viewer fails real Keycloak activation preflight");

var viewerActivator = new ViewerActivationCoordinator(viewerStore, keycloak, viewerLock);
if (await viewerActivator.ActivateAsync(Guid.NewGuid(), actor, "master") is not null)
    throw new Exception("Unknown viewer reservation must not be activated.");
var rejectedViewerActor = false;
try { await viewerActivator.ActivateAsync(viewerReservation.Id, actor, "viewer"); }
catch (ArgumentException) { rejectedViewerActor = true; }
if (!rejectedViewerActor)
    throw new Exception("Viewer actors must not activate viewer accounts.");
var rejectedUncredentialed = false;
try { await viewerActivator.ActivateAsync(viewerReservation.Id, actor, "admin"); }
catch (InvalidOperationException) { rejectedUncredentialed = true; }
if (!rejectedUncredentialed ||
    (await viewerStore.GetAsync(viewerReservation.Id))?.State != "role_assigned" ||
    (await keycloak.FindProvisionedUserAsync(viewerName))?.Enabled != false ||
    await viewerStore.IsActiveViewerSubjectAsync(viewerKeycloak.Id))
    throw new Exception("Uncredentialed viewer activation must fail before durable intent.");
Console.WriteLine("PASS unverified viewer, unknown ID and viewer-role actor cannot activate");


await using (var held = await viewerLock.TryAcquireAsync(viewerReservation.Id)
    ?? throw new Exception("Could not hold viewer activation preflight lease."))
{
    var blocked = false;
    try { await viewerReadiness.CheckAsync(viewerReservation.Id); }
    catch (ViewerProvisioningBusyException) { blocked = true; }
    if (!blocked)
        throw new Exception("Viewer readiness raced an in-progress provisioning writer.");
}
Console.WriteLine("PASS viewer activation preflight respects cross-instance advisory lease");

var reservedViewerName = "viewer-not-assigned-" + Guid.NewGuid().ToString("N")[..12];
var reservedViewer = await viewerStore.ReserveAsync(
    reservedViewerName, reservedViewerName + "@example.invalid", actor, "master");
var notAssigned = await viewerReadiness.CheckAsync(reservedViewer.Id);
if (notAssigned?.Ready != false || notAssigned.Finding != "role_not_assigned")
    throw new Exception("Reserved viewer must not pass readiness.");

// Test-only credential and email fixture. No production endpoint may do this,
// and no viewer is enabled by the readiness operation.
await keycloak.SetInitialPasswordAsync(viewerKeycloak.Id, "CI-Only-Viewer-Readiness-2026!");
var unverifiedViewer = await viewerReadiness.CheckAsync(viewerReservation.Id);
if (unverifiedViewer?.Ready != false ||
    unverifiedViewer.Finding != "email_not_verified")
    throw new Exception("Unverified viewer email incorrectly passed readiness.");
await VerifyTestEmailAsync(
    viewerKeycloak.Id, viewerName, viewerEmail, viewerReservation.Id);
var enrolledViewer = await viewerReadiness.CheckAsync(viewerReservation.Id);
if (enrolledViewer?.Ready != true ||
    enrolledViewer.Finding != "ready_for_guarded_activation" ||
    (await viewerStore.GetAsync(viewerReservation.Id))?.State != "role_assigned" ||
    (await keycloak.FindProvisionedUserAsync(viewerName))?.Enabled != false ||
    await viewerStore.IsActiveViewerSubjectAsync(viewerKeycloak.Id))
    throw new Exception("Verified viewer preflight must remain disabled and non-authorizing.");
Console.WriteLine("PASS real credentialed, email-verified viewer is ready but remains disabled and unauthorized");

await using (var held = await viewerLock.TryAcquireAsync(viewerReservation.Id)
    ?? throw new Exception("Could not hold viewer activation lease."))
{
    var blocked = false;
    try { await viewerActivator.ActivateAsync(viewerReservation.Id, actor, "master"); }
    catch (ViewerProvisioningBusyException) { blocked = true; }
    if (!blocked || (await viewerStore.GetAsync(viewerReservation.Id))?.State != "role_assigned")
        throw new Exception("Contended viewer activation mutated state.");
}
var wrongSubjectTransition = false;
try
{
    await viewerStore.MarkActivationPendingAsync(
        viewerReservation.Id, "wrong-subject", actor, "master");
}
catch (InvalidOperationException) { wrongSubjectTransition = true; }
if (!wrongSubjectTransition)
    throw new Exception("Viewer activation intent accepted a mismatched subject.");
var skippedIntent = false;
try
{
    await viewerStore.MarkActivatedAsync(
        viewerReservation.Id, viewerKeycloak.Id, actor, "master");
}
catch (InvalidOperationException) { skippedIntent = true; }
if (!skippedIntent)
    throw new Exception("Viewer activation confirmation bypassed durable intent.");

var viewerActivated = await viewerActivator.ActivateAsync(
    viewerReservation.Id, actor, "admin");
if (viewerActivated?.State != "active" || !viewerActivated.Transitioned ||
    (await viewerStore.GetAsync(viewerReservation.Id))?.State != "active" ||
    (await keycloak.FindProvisionedUserAsync(viewerName))?.Enabled != true ||
    !await viewerStore.IsActiveViewerSubjectAsync(viewerKeycloak.Id))
    throw new Exception("Verified viewer activation failed to commit database-backed access.");
var viewerRepeatActivation = await viewerActivator.ActivateAsync(
    viewerReservation.Id, actor, "master");
if (viewerRepeatActivation?.State != "active" || viewerRepeatActivation.Transitioned)
    throw new Exception("Verified viewer activation must be idempotent.");
var viewerActivationEvents = (await viewerStore.GetAuditAsync(viewerReservation.Id))
    .TakeLast(2).ToArray();
if (!viewerActivationEvents.Select(x => x.EventType)
        .SequenceEqual(["activation_pending", "active"]) ||
    viewerActivationEvents.Any(x => x.ActorSubject != actor || x.ActorRole != "admin"))
    throw new Exception("Viewer activation must record actor-attributed intent and confirmation.");
Console.WriteLine("PASS guarded viewer activation, advisory lease, conditional SQL, idempotence and audit");



await using (var auditConnection = await source.OpenConnectionAsync())
await using (var mutation = new NpgsqlCommand(
    "UPDATE oryva.viewer_provisioning_audit SET actor_role = 'admin' WHERE provisioning_id = @id",
    auditConnection))
{
    mutation.Parameters.AddWithValue("id", viewerReservation.Id);
    var blocked = false;
    try { await mutation.ExecuteNonQueryAsync(); }
    catch (PostgresException ex) when (ex.SqlState == "P0001") { blocked = true; }
    if (!blocked) throw new Exception("Viewer audit must be append-only.");
}
Console.WriteLine("PASS viewer audit updates are rejected by PostgreSQL");

// Revocation commits before Keycloak I/O and denies old viewer JWTs via DB.
var viewerDeactivator = new ViewerDeactivationCoordinator(viewerStore, keycloak, viewerLock);
if (await viewerDeactivator.DeactivateAsync(Guid.NewGuid(), actor, "master") is not null)
    throw new Exception("Unknown viewer reservation must not be deactivated.");
var unactivatedDeactivationRejected = false;
try { await viewerDeactivator.DeactivateAsync(reservedViewer.Id, actor, "admin"); }
catch (InvalidOperationException) { unactivatedDeactivationRejected = true; }
if (!unactivatedDeactivationRejected)
    throw new Exception("Unactivated viewer must not enter deactivation.");
var viewerDeactivationActorRejected = false;
try { await viewerDeactivator.DeactivateAsync(viewerReservation.Id, actor, "viewer"); }
catch (ArgumentException) { viewerDeactivationActorRejected = true; }
if (!viewerDeactivationActorRejected)
    throw new Exception("Viewer actor must not deactivate viewers.");
await using (var held = await viewerLock.TryAcquireAsync(viewerReservation.Id)
    ?? throw new Exception("Could not hold viewer deactivation lease."))
{
    var blocked = false;
    try { await viewerDeactivator.DeactivateAsync(viewerReservation.Id, actor, "master"); }
    catch (ViewerProvisioningBusyException) { blocked = true; }
    if (!blocked || !await viewerStore.IsActiveViewerSubjectAsync(viewerKeycloak.Id))
        throw new Exception("Contended viewer deactivation mutated state.");
}
var wrongViewerRevocationSubject = false;
try { await viewerStore.MarkDeactivationPendingAsync(
    viewerReservation.Id, "foreign-subject", actor, "master"); }
catch (InvalidOperationException) { wrongViewerRevocationSubject = true; }
if (!wrongViewerRevocationSubject)
    throw new Exception("Viewer revocation intent accepted foreign subject.");
var skippedViewerRevocationIntent = false;
try { await viewerStore.MarkDeactivatedAsync(
    viewerReservation.Id, viewerKeycloak.Id, actor, "master"); }
catch (InvalidOperationException) { skippedViewerRevocationIntent = true; }
if (!skippedViewerRevocationIntent)
    throw new Exception("Viewer revocation confirmation bypassed intent.");
var viewerRevoked = await viewerDeactivator.DeactivateAsync(
    viewerReservation.Id, actor, "admin");
if (viewerRevoked?.State != "deactivated" || !viewerRevoked.Transitioned ||
    (await viewerStore.GetAsync(viewerReservation.Id))?.State != "deactivated" ||
    (await keycloak.FindProvisionedUserAsync(viewerName))?.Enabled != false ||
    await viewerStore.IsActiveViewerSubjectAsync(viewerKeycloak.Id))
    throw new Exception("Viewer deactivation failed to revoke database and Keycloak access.");
var viewerRevocationRepeat = await viewerDeactivator.DeactivateAsync(
    viewerReservation.Id, actor, "master");
if (viewerRevocationRepeat?.Transitioned != false ||
    viewerRevocationRepeat.State != "deactivated")
    throw new Exception("Viewer deactivation must be idempotent.");
var viewerRevocationEvents = (await viewerStore.GetAuditAsync(viewerReservation.Id))
    .TakeLast(2).ToArray();
if (!viewerRevocationEvents.Select(x => x.EventType)
        .SequenceEqual(["deactivation_pending", "deactivated"]) ||
    viewerRevocationEvents.Any(x => x.ActorSubject != actor || x.ActorRole != "admin"))
    throw new Exception("Viewer revocation intent/completion must be actor audited.");
Console.WriteLine("PASS viewer database-first deactivation, contention, actor gate and audit");

// Simulate a lost Keycloak role-mapping response after durable intent.
// Reconciliation may adopt only the exact reserved subject and exclusive role.
var pendingViewerName = "viewer-role-retry-" + Guid.NewGuid().ToString("N")[..12];
var pendingViewer = await viewerStore.ReserveAsync(
    pendingViewerName, pendingViewerName + "@example.invalid", actor, "admin");
await keycloak.CreateDisabledViewerCandidateAsync(
    pendingViewerName, pendingViewer.Email, pendingViewer.Id);
var pendingViewerPrepared = await viewerCoordinator.RecoverAsync(pendingViewer.Id, actor, "admin")
    ?? throw new Exception("Missing pending viewer.");
await viewerStore.MarkRoleAssignmentPendingAsync(
    pendingViewer.Id, pendingViewerPrepared.KeycloakSubjectId!, actor, "admin");
await keycloak.AddViewerRoleMappingAsync(pendingViewerPrepared.KeycloakSubjectId!);
var recoveredViewerRole = await viewerRoleCoordinator.AssignAsync(
    pendingViewer.Id, actor, "master");
if (recoveredViewerRole?.State != "role_assigned" ||
    !recoveredViewerRole.Transitioned ||
    await viewerStore.IsActiveViewerSubjectAsync(pendingViewerPrepared.KeycloakSubjectId))
    throw new Exception("Durable pending viewer role was not safely reconciled.");
Console.WriteLine("PASS interrupted viewer role mapping recovered without activation");

// A successful external enablement with a lost response is not sufficient
// for authorization until a previously committed intent is reconciled.
await keycloak.SetInitialPasswordAsync(
    pendingViewerPrepared.KeycloakSubjectId!, "CI-Only-Viewer-Readiness-2026!");
await VerifyTestEmailAsync(
    pendingViewerPrepared.KeycloakSubjectId!, pendingViewerName,
    pendingViewer.Email, pendingViewer.Id);
await viewerStore.MarkActivationPendingAsync(
    pendingViewer.Id, pendingViewerPrepared.KeycloakSubjectId!, actor, "admin");
await keycloak.EnableUserAsync(pendingViewerPrepared.KeycloakSubjectId!);
if (await viewerStore.IsActiveViewerSubjectAsync(pendingViewerPrepared.KeycloakSubjectId))
    throw new Exception("Keycloak enablement without DB commit must not grant viewer access.");
var recoveredViewerActivation = await viewerActivator.ActivateAsync(
    pendingViewer.Id, actor, "master");
if (recoveredViewerActivation?.State != "active" ||
    !recoveredViewerActivation.Transitioned ||
    !await viewerStore.IsActiveViewerSubjectAsync(pendingViewerPrepared.KeycloakSubjectId))
    throw new Exception("Interrupted viewer enablement was not safely reconciled.");
var recoveredViewerEvents = (await viewerStore.GetAuditAsync(pendingViewer.Id))
    .TakeLast(2).ToArray();
if (!recoveredViewerEvents.Select(x => x.EventType)
        .SequenceEqual(["activation_pending", "active"]) ||
    recoveredViewerEvents[0].ActorRole != "admin" ||
    recoveredViewerEvents[1].ActorRole != "master")
    throw new Exception("Recovered viewer activation must preserve actual actor attribution.");
Console.WriteLine("PASS ambiguous Keycloak viewer enable response reconciles only durable intent");

// Simulate lost Keycloak disable response after database-first revocation.
// Pending state must deny access even while Keycloak is still enabled.
await viewerStore.MarkDeactivationPendingAsync(
    pendingViewer.Id, pendingViewerPrepared.KeycloakSubjectId!, actor, "master");
if (await viewerStore.IsActiveViewerSubjectAsync(pendingViewerPrepared.KeycloakSubjectId) ||
    (await keycloak.FindProvisionedUserAsync(pendingViewerName))?.Enabled != true)
    throw new Exception("Pending viewer revocation must deny access before Keycloak I/O.");
await keycloak.DisableUserAsync(pendingViewerPrepared.KeycloakSubjectId!);
var recoveredViewerRevocation = await viewerDeactivator.DeactivateAsync(
    pendingViewer.Id, actor, "admin");
if (recoveredViewerRevocation?.State != "deactivated" ||
    !recoveredViewerRevocation.Transitioned ||
    await viewerStore.IsActiveViewerSubjectAsync(pendingViewerPrepared.KeycloakSubjectId) ||
    (await keycloak.FindProvisionedUserAsync(pendingViewerName))?.Enabled != false)
    throw new Exception("Lost viewer disable response did not reconcile.");
var recoveredRevocationEvents = (await viewerStore.GetAuditAsync(pendingViewer.Id))
    .TakeLast(2).ToArray();
if (!recoveredRevocationEvents.Select(x => x.EventType)
        .SequenceEqual(["deactivation_pending", "deactivated"]) ||
    recoveredRevocationEvents[0].ActorRole != "master" ||
    recoveredRevocationEvents[1].ActorRole != "admin")
    throw new Exception("Viewer recovery audit must preserve actor attribution.");
Console.WriteLine("PASS pending viewer revocation denies JWTs and recovers lost response");

// Never adopt an externally enabled account that lacks ORYVA activation intent.
var externalViewerName = "viewer-external-enable-" + Guid.NewGuid().ToString("N")[..12];
var externalViewer = await viewerStore.ReserveAsync(
    externalViewerName, externalViewerName + "@example.invalid", actor, "master");
await keycloak.CreateDisabledViewerCandidateAsync(
    externalViewerName, externalViewer.Email, externalViewer.Id);
var externalPrepared = await viewerCoordinator.RecoverAsync(externalViewer.Id, actor, "master")
    ?? throw new Exception("External enablement fixture preparation failed.");
await viewerRoleCoordinator.AssignAsync(externalViewer.Id, actor, "master");
await keycloak.SetInitialPasswordAsync(
    externalPrepared.KeycloakSubjectId!, "CI-Only-Viewer-Readiness-2026!");
await VerifyTestEmailAsync(
    externalPrepared.KeycloakSubjectId!, externalViewerName,
    externalViewer.Email, externalViewer.Id);
await keycloak.EnableUserAsync(externalPrepared.KeycloakSubjectId!);
var externalEnableRejected = false;
try { await viewerActivator.ActivateAsync(externalViewer.Id, actor, "master"); }
catch (InvalidOperationException) { externalEnableRejected = true; }
if (!externalEnableRejected ||
    (await viewerStore.GetAsync(externalViewer.Id))?.State != "role_assigned" ||
    await viewerStore.IsActiveViewerSubjectAsync(externalPrepared.KeycloakSubjectId))
    throw new Exception("External enablement without durable intent must fail closed.");
Console.WriteLine("PASS externally enabled viewer cannot bypass durable activation intent");


var conflictViewerName = "viewer-role-conflict-" + Guid.NewGuid().ToString("N")[..12];
var conflictViewer = await viewerStore.ReserveAsync(
    conflictViewerName, conflictViewerName + "@example.invalid", actor, "master");
await keycloak.CreateDisabledViewerCandidateAsync(
    conflictViewerName, conflictViewer.Email, conflictViewer.Id);
var conflictPrepared = await viewerCoordinator.RecoverAsync(conflictViewer.Id, actor, "master")
    ?? throw new Exception("Missing conflict viewer.");
await keycloak.AddAdminRoleMappingAsync(conflictPrepared.KeycloakSubjectId!);
var conflictRejected = false;
try { await viewerRoleCoordinator.AssignAsync(conflictViewer.Id, actor, "admin"); }
catch (InvalidOperationException) { conflictRejected = true; }
if (!conflictRejected ||
    (await viewerStore.GetAsync(conflictViewer.Id))?.State != "prepared" ||
    await viewerStore.IsActiveViewerSubjectAsync(conflictPrepared.KeycloakSubjectId))
    throw new Exception("Unexpected admin role must block viewer assignment.");
Console.WriteLine("PASS conflicting Keycloak admin role fails closed for viewer");

var missingViewerName = "viewer-missing-" + Guid.NewGuid().ToString("N")[..12];
var missingViewer = await viewerStore.ReserveAsync(
    missingViewerName, missingViewerName + "@example.invalid", actor, "admin");
var missingViewerRejected = false;
try { await viewerCoordinator.RecoverAsync(missingViewer.Id, actor, "admin"); }
catch (InvalidOperationException) { missingViewerRejected = true; }
if (!missingViewerRejected || (await viewerStore.GetAsync(missingViewer.Id))?.State != "reserved")
    throw new Exception("Missing Keycloak viewer must remain reserved.");
Console.WriteLine("PASS missing viewer identity is never silently adopted");

var foreignViewerName = "viewer-foreign-" + Guid.NewGuid().ToString("N")[..12];
var foreignViewer = await viewerStore.ReserveAsync(
    foreignViewerName, foreignViewerName + "@example.invalid", actor, "admin");
await keycloak.CreateDisabledViewerCandidateAsync(
    foreignViewerName, foreignViewer.Email, Guid.NewGuid());
var foreignRejected = false;
try { await viewerCoordinator.RecoverAsync(foreignViewer.Id, actor, "admin"); }
catch (InvalidOperationException) { foreignRejected = true; }
if (!foreignRejected || (await viewerStore.GetAsync(foreignViewer.Id))?.State != "reserved")
    throw new Exception("Unowned Keycloak viewer was adopted.");
Console.WriteLine("PASS mismatched Keycloak ownership marker cannot prepare viewer");

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
