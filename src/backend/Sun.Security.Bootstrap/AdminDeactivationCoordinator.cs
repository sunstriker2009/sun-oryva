namespace Sun.Security.Bootstrap;

/// <summary>
/// Database-first, master-authorized admin revocation. Runtime authorization
/// is revoked before Keycloak I/O. Ambiguous remote responses remain pending
/// and can be reconciled by retrying under the same cross-instance lease.
/// </summary>
public sealed class AdminDeactivationCoordinator(
    AdminProvisioningStore reservations,
    KeycloakManagementClient keycloak,
    AdminProvisioningLock provisioningLock)
{
    public async Task<AdminDeactivationResult?> DeactivateAsync(
        Guid id, string actorSubject, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new AdminProvisioningBusyException();
        var state = await reservations.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("active" or "deactivation_pending" or "deactivated") ||
            string.IsNullOrWhiteSpace(state.KeycloakSubjectId))
            throw new InvalidOperationException("Admin reservation is not eligible for deactivation.");

        if (state.State == "active")
        {
            // This is the revocation boundary for already-issued admin JWTs.
            // Never call Keycloak before the DB state and audit commit.
            await lease.EnsureHeldAsync(cancellationToken);
            await reservations.MarkDeactivationPendingAsync(
                id, state.KeycloakSubjectId, actorSubject, cancellationToken);
            state = state with { State = "deactivation_pending" };
        }

        var user = await RequireOwnedAsync(state, cancellationToken);
        if (user.Enabled)
        {
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.DisableUserAsync(state.KeycloakSubjectId!, cancellationToken);
        }
        await RequireOwnedAndDisabledAsync(state, cancellationToken);
        await lease.EnsureHeldAsync(cancellationToken);
        // Logout revokes refresh tokens and server sessions. A lost response
        // leaves the DB pending; a retry can safely call logout again.
        await keycloak.LogoutUserSessionsAsync(state.KeycloakSubjectId!, cancellationToken);
        await RequireOwnedAndDisabledAsync(state, cancellationToken);

        if (state.State == "deactivated")
            return new AdminDeactivationResult(id, "deactivated", false);

        await lease.EnsureHeldAsync(cancellationToken);
        await reservations.MarkDeactivatedAsync(
            id, state.KeycloakSubjectId!, actorSubject, cancellationToken);
        return new AdminDeactivationResult(id, "deactivated", true);
    }

    private async Task RequireOwnedAndDisabledAsync(
        AdminProvisioningState state, CancellationToken cancellationToken)
    {
        var user = await RequireOwnedAsync(state, cancellationToken);
        if (user.Enabled)
            throw new InvalidOperationException("Keycloak identity remains enabled.");
    }

    private async Task<KeycloakUser> RequireOwnedAsync(
        AdminProvisioningState state, CancellationToken cancellationToken)
    {
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null ||
            !string.Equals(user.Id, state.KeycloakSubjectId, StringComparison.Ordinal) ||
            !string.Equals(user.Username, state.Username, StringComparison.Ordinal) ||
            !string.Equals(user.Email, state.Email, StringComparison.OrdinalIgnoreCase) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
            markers.Count != 1 ||
            !string.Equals(markers[0], state.Id.ToString("D"), StringComparison.Ordinal))
            throw new InvalidOperationException("Admin deactivation ownership mismatch.");
        return user;
    }
}

public sealed record AdminDeactivationResult(
    Guid ProvisioningId, string State, bool Transitioned);
