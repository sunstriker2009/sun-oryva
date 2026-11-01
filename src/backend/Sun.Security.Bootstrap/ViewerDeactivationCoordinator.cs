namespace Sun.Security.Bootstrap;

/// <summary>
/// Database-first viewer revocation. HTTP callers must be database-active
/// master/admin; a committed pending state immediately denies stale viewer JWTs.
/// Interrupted Keycloak operations are reconciled under the viewer advisory lease.
/// </summary>
public sealed class ViewerDeactivationCoordinator(
    ViewerAccountStore accounts,
    KeycloakManagementClient keycloak,
    ViewerProvisioningLock provisioningLock)
{
    public async Task<ViewerDeactivationResult?> DeactivateAsync(
        Guid id, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        if (actorRole is not ("master" or "admin"))
            throw new ArgumentException("Only active master/admin may deactivate viewers.", nameof(actorRole));

        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new ViewerProvisioningBusyException();
        var state = await accounts.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("active" or "deactivation_pending" or "deactivated") ||
            string.IsNullOrWhiteSpace(state.KeycloakSubjectId))
            throw new InvalidOperationException("Viewer is not eligible for deactivation.");

        if (state.State == "active")
        {
            // Commit revocation and audit BEFORE contacting Keycloak.
            await lease.EnsureHeldAsync(cancellationToken);
            await accounts.MarkDeactivationPendingAsync(
                id, state.KeycloakSubjectId!, actorSubject, actorRole, cancellationToken);
            state = state with { State = "deactivation_pending" };
        }

        // Do not require a specific role to revoke an owned identity:
        // external privilege drift must not block disablement.
        var user = await RequireOwnedAsync(state, cancellationToken);
        if (user.Enabled)
        {
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.DisableUserAsync(state.KeycloakSubjectId!, cancellationToken);
        }
        await RequireOwnedAndDisabledAsync(state, cancellationToken);
        await lease.EnsureHeldAsync(cancellationToken);
        await keycloak.LogoutUserSessionsAsync(state.KeycloakSubjectId!, cancellationToken);
        await RequireOwnedAndDisabledAsync(state, cancellationToken);

        if (state.State == "deactivated")
            return new ViewerDeactivationResult(id, "deactivated", false);

        await lease.EnsureHeldAsync(cancellationToken);
        await accounts.MarkDeactivatedAsync(
            id, state.KeycloakSubjectId!, actorSubject, actorRole, cancellationToken);
        return new ViewerDeactivationResult(id, "deactivated", true);
    }

    private async Task RequireOwnedAndDisabledAsync(
        ViewerAccountState state, CancellationToken cancellationToken)
    {
        if ((await RequireOwnedAsync(state, cancellationToken)).Enabled)
            throw new InvalidOperationException("Keycloak viewer remains enabled.");
    }

    private async Task<KeycloakUser> RequireOwnedAsync(
        ViewerAccountState state, CancellationToken cancellationToken)
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
            throw new InvalidOperationException("Viewer deactivation ownership mismatch.");
        return user;
    }
}

public sealed record ViewerDeactivationResult(
    Guid ProvisioningId, string State, bool Transitioned);
