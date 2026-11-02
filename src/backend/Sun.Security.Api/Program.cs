using Microsoft.AspNetCore.Authorization;
using Sun.Security.Api;
using Npgsql;
using Sun.Security.AspNetCore;
using Sun.Security.Bootstrap;

var builder = WebApplication.CreateBuilder(args);
var issuer = builder.Configuration["ORYVA_OIDC_ISSUER"]
    ?? throw new InvalidOperationException("ORYVA_OIDC_ISSUER must be configured.");
var audience = builder.Configuration["ORYVA_OIDC_AUDIENCE"]
    ?? throw new InvalidOperationException("ORYVA_OIDC_AUDIENCE must be configured.");
var databaseUrl = builder.Configuration["ORYVA_DATABASE_URL"]
    ?? throw new InvalidOperationException("ORYVA_DATABASE_URL must be configured.");

builder.Services.AddSingleton(NpgsqlDataSource.Create(databaseUrl));
builder.Services.AddScoped<MasterReservationStore>();
builder.Services.AddScoped<AdminProvisioningStore>();
builder.Services.AddScoped<AdminProvisioningLock>();
builder.Services.AddScoped<AdminProvisioningReconciler>();
builder.Services.AddScoped<AdminRoleAssignmentCoordinator>();
builder.Services.AddScoped<AdminActivationReadiness>();
builder.Services.AddScoped<AdminActivationCoordinator>();
builder.Services.AddScoped<AdminDeactivationCoordinator>();
builder.Services.AddScoped<ViewerProvisioningLock>();
builder.Services.AddScoped<ViewerPreparationCoordinator>();
builder.Services.AddScoped<ViewerRoleAssignmentCoordinator>();
builder.Services.AddScoped<ViewerActivationReadiness>();
builder.Services.AddScoped<ViewerActivationCoordinator>();
builder.Services.AddScoped<ViewerDeactivationCoordinator>();
builder.Services.AddOryvaKeycloakJwt(new OryvaJwtOptions { Issuer = issuer, Audience = audience });
builder.Services.AddOryvaActiveMasterPolicy();
builder.Services.AddOryvaRolePolicies();
var writeLimitSetting = builder.Configuration["ORYVA_MANAGEMENT_WRITE_LIMIT_PER_MINUTE"];
if (writeLimitSetting is not null &&
    (!int.TryParse(writeLimitSetting, out var configuredLimit) ||
     configuredLimit is < 1 or > 120))
    throw new InvalidOperationException(
        "ORYVA_MANAGEMENT_WRITE_LIMIT_PER_MINUTE must be an integer between 1 and 120.");
builder.Services.AddOryvaManagementRateLimiting(
    writeLimitSetting is null ? 10 : int.Parse(writeLimitSetting));


// Optional management configuration: endpoints are not exposed unless all
// settings are supplied. Never place service credentials in source control.
var managementUrl = builder.Configuration["ORYVA_KEYCLOAK_MANAGEMENT_URL"];
var managementClientId = builder.Configuration["ORYVA_KEYCLOAK_MANAGEMENT_CLIENT_ID"];
var managementSecret = builder.Configuration["ORYVA_KEYCLOAK_MANAGEMENT_CLIENT_SECRET"];
var managementConfigured = managementUrl is not null ||
    managementClientId is not null || managementSecret is not null;
if (managementConfigured)
{
    if (!Uri.TryCreate(managementUrl, UriKind.Absolute, out var managementUri) ||
        string.IsNullOrWhiteSpace(managementClientId) ||
        string.IsNullOrWhiteSpace(managementSecret))
        throw new InvalidOperationException("Complete Keycloak management configuration is required.");
    var managementOptions = new KeycloakManagementOptions
    {
        BaseAddress = managementUri,
        ClientId = managementClientId,
        ClientSecret = managementSecret
    };
    managementOptions.Validate();
    builder.Services.AddSingleton(managementOptions);
    builder.Services.AddHttpClient<KeycloakManagementClient>()
        .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        });
}

var app = builder.Build();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
// Authenticate and authorize before consuming the caller's write quota.
app.UseRateLimiter();

// Anonymous liveness probe; deliberately exposes no identity information.
app.MapGet("/health/live", () => Results.Ok(new { status = "alive" }))
    .AllowAnonymous();

// Demonstrates policy enforcement without mutating any account state.
app.MapGet("/api/master/session", (System.Security.Claims.ClaimsPrincipal principal) =>
    Results.Ok(new { subject = principal.FindFirst("sub")?.Value, role = "master" }))
    .RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);

// Demonstrates the active-admin authorization boundary. A validated admin JWT
// is insufficient unless the exact subject is active in PostgreSQL.
app.MapGet("/api/admin/session", (System.Security.Claims.ClaimsPrincipal principal) =>
    Results.Ok(new { subject = principal.FindFirst("sub")?.Value, role = "admin" }))
    .RequireAuthorization(OryvaRolePolicyExtensions.Admin);

// Read-only viewer boundary: an exclusive Keycloak viewer role requires an
// active PostgreSQL viewer record. Active admins inherit read-only access.
app.MapGet("/api/viewer/session", (System.Security.Claims.ClaimsPrincipal principal) =>
    Results.Ok(new { subject = principal.FindFirst("sub")?.Value, access = "viewer" }))
    .RequireAuthorization(OryvaRolePolicyExtensions.Viewer);

// Administrative provisioning endpoints are guarded by the active-master policy.
// Invitations and self-service enrollment remain separate future operations.
if (managementConfigured)
{
    // Viewer management: only active master or database-active admin may prepare.
    // Viewer preparation never grants a realm role, credential or access.
    app.MapPost("/api/viewers/prepare", async (
        PrepareViewerRequest input, ViewerPreparationCoordinator coordinator,
        IAuthorizationService authorization,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        var actorRole = await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal);
        if (actorRole is null) return Results.Forbid();
        var subjects = principal.FindAll("sub").Select(x => x.Value).ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0]))
            return Results.Forbid();
        if (!AdminPreparationValidation.IsValid(input.Username, input.Email))
            return Results.BadRequest(new { error = "Valid username and email are required." });
        try
        {
            var result = await coordinator.PrepareAsync(
                input.Username, input.Email, subjects[0], actorRole, cancellationToken);
            return Results.Accepted(value: new {
                provisioningId = result.Id, status = result.State,
                nextStep = "Assign the viewer role, then complete separate credential enrollment and activation."
            });
        }
        catch (ViewerReservationConflictException)
        {
            return Results.Conflict(new { error = "Viewer identity already reserved." });
        }
        catch (ViewerPreparationPendingException pending)
        {
            return Results.Conflict(new {
                provisioningId = pending.ProvisioningId,
                status = "reserved",
                error = "Viewer preparation incomplete; use the recovery endpoint."
            });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new {
                error = "Viewer preparation incomplete; reconcile the reserved identity."
            });
        }
    }).RequireAuthorization().RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    app.MapPost("/api/viewers/provisioning/{id:guid}/recover", async (
        Guid id, ViewerPreparationCoordinator coordinator,
        IAuthorizationService authorization,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        if (await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal) is null)
            return Results.Forbid();
        try
        {
            var result = await coordinator.RecoverAsync(id, cancellationToken);
            return result is null ? Results.NotFound() :
                Results.Ok(new { provisioningId = result.Id, status = result.State });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new { error = "Viewer ownership verification failed." });
        }
    }).RequireAuthorization().RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    // Viewer role assignment requires an active master or database-active admin.
    // The coordinator persists intent and verifies an exclusively viewer-mapped,
    // disabled Keycloak candidate. This never activates or credentials an account.
    app.MapPost("/api/viewers/provisioning/{id:guid}/assign-viewer-role", async (
        Guid id, ViewerRoleAssignmentCoordinator coordinator,
        IAuthorizationService authorization,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        var actorRole = await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal);
        if (actorRole is null) return Results.Forbid();
        var subjects = principal.FindAll("sub").Select(x => x.Value).ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0]))
            return Results.Forbid();
        try
        {
            var result = await coordinator.AssignAsync(
                id, subjects[0], actorRole, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (ViewerProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Viewer provisioning operation already in progress." });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new { error = "Viewer role assignment pending or rejected; inspect provisioning state." });
        }
    }).RequireAuthorization().RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    // Read-only viewer activation preflight. This result is not a grant or
    // authorization token; a future activation operation must recheck all gates.
    app.MapGet("/api/viewers/provisioning/{id:guid}/activation-readiness", async (
        Guid id, ViewerActivationReadiness readiness,
        IAuthorizationService authorization,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        if (await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal) is null)
            return Results.Forbid();
        try
        {
            var result = await readiness.CheckAsync(id, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (ViewerProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Viewer provisioning operation already in progress." });
        }
    }).RequireAuthorization();

    // Activation is a separate privileged mutation, not a readiness result.
    // The coordinator reacquires the viewer lease, repeats every Keycloak gate,
    // commits durable intent before enablement and verifies enablement before
    // granting database-backed viewer access. No credentials are enrolled here.
    app.MapPost("/api/viewers/provisioning/{id:guid}/activate", async (
        Guid id, ViewerActivationCoordinator coordinator,
        IAuthorizationService authorization,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        var actorRole = await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal);
        if (actorRole is null) return Results.Forbid();
        var subjects = principal.FindAll("sub").Select(x => x.Value).ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0]))
            return Results.Forbid();
        try
        {
            var result = await coordinator.ActivateAsync(
                id, subjects[0], actorRole, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (ViewerProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Viewer provisioning operation already in progress." });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new { error = "Viewer activation pending or rejected; inspect provisioning state." });
        }
    }).RequireAuthorization().RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    // Revocation is committed in PostgreSQL before Keycloak disable/logout.
    // A stale viewer JWT cannot authorize after the pending state is committed.
    app.MapPost("/api/viewers/provisioning/{id:guid}/deactivate", async (
        Guid id, ViewerDeactivationCoordinator coordinator,
        IAuthorizationService authorization,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        var actorRole = await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal);
        if (actorRole is null) return Results.Forbid();
        var subjects = principal.FindAll("sub").Select(x => x.Value).ToArray();
        if (subjects.Length != 1 || string.IsNullOrWhiteSpace(subjects[0]))
            return Results.Forbid();
        try
        {
            var result = await coordinator.DeactivateAsync(
                id, subjects[0], actorRole, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (ViewerProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Viewer provisioning operation already in progress." });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new { error = "Viewer deactivation pending or rejected; inspect provisioning state." });
        }
    }).RequireAuthorization().RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    app.MapGet("/api/viewers/provisioning/{id:guid}/audit", async (
        Guid id, ViewerAccountStore accounts,
        IAuthorizationService authorization,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        if (await ViewerManagerAuthorization.GetActorRoleAsync(authorization, principal) is null)
            return Results.Forbid();
        if (await accounts.GetAsync(id, cancellationToken) is null)
            return Results.NotFound();
        return Results.Ok(new { provisioningId = id, events = await accounts.GetAuditAsync(id, cancellationToken) });
    }).RequireAuthorization();

    // Read-only recovery inspection: no Keycloak mutations or implicit adoption.
    app.MapGet("/api/master/admins/provisioning/{id:guid}", async (
        Guid id, AdminProvisioningReconciler reconciler,
        CancellationToken cancellationToken) =>
    {
        var result = await reconciler.InspectAsync(id, cancellationToken);
        return result is null ? Results.NotFound() : Results.Ok(result);
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);

    // Audit access is master-only; no credentials or Keycloak payloads are stored.
    app.MapGet("/api/master/admins/provisioning/{id:guid}/events", async (
        Guid id, AdminProvisioningStore reservations,
        CancellationToken cancellationToken) =>
    {
        if (await reservations.GetAsync(id, cancellationToken) is null)
            return Results.NotFound();
        var events = await reservations.GetAuditAsync(id, cancellationToken);
        return Results.Ok(new { provisioningId = id, events });
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);

    // Explicit recovery is restricted to the active master. It does not
    // mutate Keycloak or grant privileges.
    app.MapPost("/api/master/admins/provisioning/{id:guid}/recover", async (
        Guid id, AdminProvisioningReconciler reconciler,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var result = await reconciler.RecoverAsync(id, cancellationToken);
            return result is null ? Results.NotFound() :
                !result.IdentityVerified ? Results.Conflict(result) : Results.Ok(result);
        }
        catch (AdminProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Provisioning recovery already in progress." });
        }
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName).RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    // Read-only preflight. The result is never an authorization token and
    // cannot enable an account; activation must repeat all checks.
    app.MapGet("/api/master/admins/provisioning/{id:guid}/activation-readiness", async (
        Guid id, AdminActivationReadiness readiness,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var result = await readiness.CheckAsync(id, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (AdminProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Provisioning operation already in progress." });
        }
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);

    // Master-only activation. Rechecks all Keycloak conditions under the lease,
    // persists intent before enablement and reconciles ambiguous remote writes.
    app.MapPost("/api/master/admins/provisioning/{id:guid}/activate", async (
        Guid id, AdminActivationCoordinator coordinator,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var result = await coordinator.ActivateAsync(id, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (AdminProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Provisioning operation already in progress." });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new { error = "Activation rejected; inspect provisioning state." });
        }
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName).RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    // Database-first revocation: immediately denies existing admin JWTs,
    // then disables Keycloak identity and logs out sessions.
    app.MapPost("/api/master/admins/provisioning/{id:guid}/deactivate", async (
        Guid id, AdminDeactivationCoordinator coordinator,
        System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        var actor = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(actor))
            return Results.Forbid();
        try
        {
            var result = await coordinator.DeactivateAsync(id, actor, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (AdminProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Provisioning operation already in progress." });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new { error = "Deactivation pending or rejected; inspect provisioning state." });
        }
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName).RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    // Assign only the admin realm role to a disabled, credentialless, owned
    // identity. Never enables the user or sends an invitation.
    app.MapPost("/api/master/admins/provisioning/{id:guid}/assign-admin-role", async (
        Guid id, AdminRoleAssignmentCoordinator coordinator,
        CancellationToken cancellationToken) =>
    {
        try
        {
            var result = await coordinator.AssignAsync(id, cancellationToken);
            return result is null ? Results.NotFound() : Results.Ok(result);
        }
        catch (AdminProvisioningBusyException)
        {
            return Results.Conflict(new { error = "Provisioning operation already in progress." });
        }
        catch (InvalidOperationException)
        {
            return Results.Conflict(new { error = "Role assignment rejected; inspect provisioning state." });
        }
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName).RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);

    app.MapPost("/api/master/admins/prepare", async (
        PrepareAdminRequest input, KeycloakManagementClient management,
        AdminProvisioningStore reservations, System.Security.Claims.ClaimsPrincipal principal,
        CancellationToken cancellationToken) =>
    {
        if (!AdminPreparationValidation.IsValid(input.Username, input.Email))
            return Results.BadRequest(new { error = "Valid username and email are required." });

        var actor = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrWhiteSpace(actor))
            return Results.Forbid();
        var reservation = await reservations.ReserveAsync(
            input.Username, input.Email, actor, cancellationToken);
        // Keycloak is an external system: a failed/lost response is ambiguous.
        // Always mark the reservation for reconciliation before retrying.
        try
        {
            await management.CreateDisabledAdminCandidateAsync(
                input.Username, input.Email, reservation.Id, cancellationToken);
        }
        catch
        {
            await reservations.MarkReconciliationRequiredAsync(
                reservation.Id, CancellationToken.None);
            throw;
        }
        await reservations.MarkReconciliationRequiredAsync(
            reservation.Id, cancellationToken);
        // Read the canonical Keycloak user after creation. The subject is bound
        // only when the identity is exact and still disabled. Ownership marker
        // validation is a separate mandatory gate before role assignment.
        var created = await management.FindProvisionedUserAsync(
            input.Username, cancellationToken);
        if (created is null || created.Enabled || string.IsNullOrWhiteSpace(created.Id) ||
            created.Attributes is null ||
            !created.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
            markers.Count != 1 ||
            !string.Equals(markers[0], reservation.Id.ToString("D"), StringComparison.Ordinal))
            throw new InvalidOperationException("Keycloak provisioning ownership could not be verified.");
        if (!string.Equals(created.Email, input.Email, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Keycloak provisioning email mismatch.");
        var existingRoles = await management.GetDirectOryvaRolesAsync(
            created.Id, cancellationToken);
        if (existingRoles.Count != 0)
            throw new InvalidOperationException("Admin candidate already has an ORYVA realm role.");
        var effectiveRoles = await management.GetEffectiveOryvaRolesAsync(
            created.Id, cancellationToken);
        if (effectiveRoles.Count != 0)
            throw new InvalidOperationException(
                "Admin candidate inherits an ORYVA realm role; preparation denied.");
        await reservations.BindVerifiedSubjectAsync(
            reservation.Id, input.Username, input.Email, actor, created.Id, cancellationToken);
        await reservations.MarkPreparedAsync(reservation.Id, created.Id, cancellationToken);
        return Results.Accepted(value: new
        {
            provisioningId = reservation.Id,
            status = "prepared",
            nextStep = "Assign the admin role, enroll credentials, then request guarded activation."
        });
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName).RequireRateLimiting(OryvaManagementRateLimiting.PolicyName);
}

app.Run();

public sealed record PrepareAdminRequest(string Username, string Email);
public sealed record PrepareViewerRequest(string Username, string Email);

public partial class Program;
