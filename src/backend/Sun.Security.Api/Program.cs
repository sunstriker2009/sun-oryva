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
            await management.CreateDisabledUserAsync(
                input.Username, input.Email, cancellationToken);
        }
        catch
        {
            await reservations.MarkReconciliationRequiredAsync(
                reservation.Id, CancellationToken.None);
            throw;
        }
        await reservations.MarkReconciliationRequiredAsync(
            reservation.Id, cancellationToken);
        return Results.Accepted(value: new
        {
            provisioningId = reservation.Id,
            status = "reconciliation_required",
            nextStep = "Verify Keycloak ownership before role assignment or activation."
        });
    }).RequireAuthorization(ActiveMasterPolicyExtensions.PolicyName);
}

app.Run();

public sealed record PrepareAdminRequest(string Username, string Email);

public partial class Program;
