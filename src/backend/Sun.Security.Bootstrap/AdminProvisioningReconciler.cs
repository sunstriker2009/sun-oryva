namespace Sun.Security.Bootstrap;

/// <summary>
/// Read-only recovery inspection. Never creates, adopts, enables or assigns roles.
/// All mismatches fail closed and leave the reservation untouched.
/// </summary>
public sealed class AdminProvisioningReconciler(
    AdminProvisioningStore reservations, KeycloakManagementClient keycloak)
{
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
