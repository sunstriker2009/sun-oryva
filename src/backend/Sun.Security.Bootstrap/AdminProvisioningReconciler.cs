namespace Sun.Security.Bootstrap;

/// <summary>
/// Read-only recovery inspection. Never creates, adopts, enables or assigns roles.
/// All mismatches fail closed and leave the reservation untouched.
/// </summary>
public sealed class AdminProvisioningReconciler(
    AdminProvisioningStore reservations, KeycloakManagementClient keycloak,
    AdminProvisioningLock provisioningLock)
{
    /// <summary>
    /// Revalidates a previously created, disabled and marker-owned identity.
    /// Only advances an existing reconciliation reservation; never creates users.
    /// </summary>
    public async Task<AdminProvisioningInspection?> RecoverAsync(
        Guid reservationId, CancellationToken cancellationToken = default)
    {
        await using var lease = await provisioningLock.TryAcquireAsync(reservationId, cancellationToken)
            ?? throw new AdminProvisioningBusyException();

        // The reservation is loaded only after acquiring the cross-instance lease.
        var state = await reservations.GetAsync(reservationId, cancellationToken);
        if (state is null) return null;
        if (state.State == "prepared")
            return await InspectAsync(reservationId, cancellationToken);
        if (state.State != "reconciliation_required")
            throw new InvalidOperationException("Reservation is not eligible for recovery.");

        var inspection = await InspectAsync(reservationId, cancellationToken);
        if (inspection is null || !inspection.IdentityVerified)
            return inspection;

        // Repeat the complete role and identity verification immediately before
        // binding. External Keycloak administrators are outside this lock's scope.
        var verified = await InspectAsync(reservationId, cancellationToken);
        if (verified is null || !verified.IdentityVerified)
            return verified;
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken)
            ?? throw new InvalidOperationException("Keycloak identity disappeared during recovery.");
        if (user.Enabled || string.IsNullOrWhiteSpace(user.Id) ||
            !string.Equals(user.Username, state.Username, StringComparison.Ordinal) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
            markers.Count != 1 || markers[0] != reservationId.ToString("D") ||
            !string.Equals(user.Email, state.Email, StringComparison.OrdinalIgnoreCase) ||
            (state.KeycloakSubjectId is not null &&
             !string.Equals(state.KeycloakSubjectId, user.Id, StringComparison.Ordinal)))
            throw new InvalidOperationException("Keycloak identity changed during recovery.");

        await lease.EnsureHeldAsync(cancellationToken);
        await reservations.BindReconciledSubjectAsync(reservationId, user.Id, cancellationToken);
        await lease.EnsureHeldAsync(cancellationToken);
        await reservations.MarkPreparedAsync(reservationId, user.Id, cancellationToken);
        return await InspectAsync(reservationId, cancellationToken);
    }

    public async Task<AdminProvisioningInspection?> InspectAsync(
        Guid reservationId, CancellationToken cancellationToken = default)
    {
        var state = await reservations.GetAsync(reservationId, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("reserved" or "reconciliation_required" or "prepared"))
            throw new InvalidOperationException("Unknown admin provisioning state.");
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null)
            return new AdminProvisioningInspection(reservationId, state.State,
                "identity_missing", false);
        if (user.Enabled || string.IsNullOrWhiteSpace(user.Id) ||
            !string.Equals(user.Username, state.Username, StringComparison.Ordinal) ||
            !string.Equals(user.Email, state.Email, StringComparison.OrdinalIgnoreCase) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
            markers.Count != 1 ||
            !string.Equals(markers[0], state.Id.ToString("D"), StringComparison.Ordinal) ||
            (state.KeycloakSubjectId is not null &&
             !string.Equals(state.KeycloakSubjectId, user.Id, StringComparison.Ordinal)))
            return new AdminProvisioningInspection(reservationId, state.State,
                "identity_mismatch", false);
        var direct = await keycloak.GetDirectOryvaRolesAsync(user.Id, cancellationToken);
        var effective = await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken);
        if (direct.Count != 0 || effective.Count != 0)
            return new AdminProvisioningInspection(reservationId, state.State,
                "unexpected_role", false);
        return new AdminProvisioningInspection(reservationId, state.State,
            "verified_disabled_candidate", true);
    }
}

public sealed record AdminProvisioningInspection(
    Guid ProvisioningId, string State, string Finding, bool IdentityVerified);
