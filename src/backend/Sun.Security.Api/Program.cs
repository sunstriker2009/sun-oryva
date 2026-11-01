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
builder.Services.AddOryvaKeycloakJwt(new OryvaJwtOptions { Issuer = issuer, Audience = audience });
builder.Services.AddOryvaActiveMasterPolicy();
builder.Services.AddOryvaRolePolicies();

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
app.UseAuthentication();
app.UseAuthorization();

// Anonymous liveness probe; deliberately exposes no identity information.
app.MapGet("/health/live", () => Results.Ok(new { status = "alive" }))
    .AllowAnonymous();

// Demonstrates policy enforcement without mutating any account state.
app.MapGet("/api/master/session", (System.Security.Claims.ClaimsPrincipal principal) =>
    Results.Ok(new { subject = principal.FindFirst("sub")?.Value, role = "master" }))
    .RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);

// Phase 1 only: prepare a disabled account. Role assignment, activation,
// invitations and idempotent reconciliation are separate future operations.
if (managementConfigured)
{
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
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);

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
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);

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
            nextStep = "Admin role assignment and activation are not yet implemented."
        });
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);
}

app.Run();

public sealed record PrepareAdminRequest(string Username, string Email);

public partial class Program;
