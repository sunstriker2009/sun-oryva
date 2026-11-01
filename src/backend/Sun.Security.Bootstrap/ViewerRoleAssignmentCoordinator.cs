namespace Sun.Security.Bootstrap;

/// <summary>
/// Coordinates disabled viewer realm-role assignment only. The HTTP boundary
/// requires an active master or database-active admin, and supplies the actor.
/// A durable PostgreSQL intent precedes Keycloak mutation. No account enablement,
/// password enrollment, or viewer API authorization occurs in this workflow.
/// </summary>
public sealed class ViewerRoleAssignmentCoordinator(
    ViewerAccountStore accounts, KeycloakManagementClient keycloak,
    ViewerProvisioningLock provisioningLock)
{
    public async Task<ViewerRoleAssignmentResult?> AssignAsync(
        Guid id, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        if (actorRole is not ("master" or "admin"))
            throw new ArgumentException("Only master or admin can manage viewers.", nameof(actorRole));

        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new ViewerProvisioningBusyException();
        var state = await accounts.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("prepared" or "role_assignment_pending" or "role_assigned"))
            throw new InvalidOperationException("Viewer reservation is not prepared for role assignment.");

        var hasViewerRole = await VerifyDisabledOwnedCandidateAsync(state, cancellationToken);
        if (state.State == "role_assigned")
        {
            if (!hasViewerRole)
                throw new InvalidOperationException("Persisted viewer role no longer matches Keycloak.");
            return new ViewerRoleAssignmentResult(id, "role_assigned", false);
        }

        if (state.State == "prepared")
        {
            if (hasViewerRole)
                throw new InvalidOperationException("Unexpected pre-existing viewer role.");
            await lease.EnsureHeldAsync(cancellationToken);
            await accounts.MarkRoleAssignmentPendingAsync(
                id, state.KeycloakSubjectId!, actorSubject, actorRole, cancellationToken);
            state = state with { State = "role_assignment_pending" };
        }

        if (!hasViewerRole)
        {
            // Repeat ownership, disabled, credential and direct/effective role
            // checks immediately before the external privilege mutation.
            if (await VerifyDisabledOwnedCandidateAsync(state, cancellationToken))
                throw new InvalidOperationException("Viewer role changed during assignment.");
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.AddViewerRoleMappingAsync(state.KeycloakSubjectId!, cancellationToken);
        }

        // Never infer success from Keycloak's POST response alone. If the
        // response was lost, the durable pending row permits explicit retry.
        if (!await VerifyDisabledOwnedCandidateAsync(state, cancellationToken))
            throw new InvalidOperationException("Keycloak viewer role was not verified.");
        await lease.EnsureHeldAsync(cancellationToken);
        await accounts.MarkRoleAssignedAsync(
            id, state.KeycloakSubjectId!, actorSubject, actorRole, cancellationToken);
        return new ViewerRoleAssignmentResult(id, "role_assigned", true);
    }

    private async Task<bool> VerifyDisabledOwnedCandidateAsync(
        ViewerAccountState state, CancellationToken cancellationToken)
    {
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null || user.Enabled || user.EmailVerified ||
            string.IsNullOrWhiteSpace(user.Id) ||
            string.IsNullOrWhiteSpace(state.KeycloakSubjectId) ||
            !string.Equals(user.Id, state.KeycloakSubjectId, StringComparison.Ordinal) ||
            !string.Equals(user.Username, state.Username, StringComparison.Ordinal) ||
            !string.Equals(user.Email, state.Email, StringComparison.OrdinalIgnoreCase) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
            markers.Count != 1 ||
            !string.Equals(markers[0], state.Id.ToString("D"), StringComparison.Ordinal))
            throw new InvalidOperationException("Viewer candidate ownership or disabled state mismatch.");

        if (await keycloak.HasPasswordCredentialAsync(user.Id, cancellationToken))
            throw new InvalidOperationException("Viewer candidate already has a password.");

        var direct = await keycloak.GetDirectOryvaRolesAsync(user.Id, cancellationToken);
        var effective = await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken);
        var noRole = direct.Count == 0 && effective.Count == 0;
        var onlyViewer = direct.Count == 1 && direct[0] == "viewer" &&
                         effective.Count == 1 && effective[0] == "viewer";
        if (!noRole && !onlyViewer)
            throw new InvalidOperationException("Conflicting ORYVA realm roles on viewer candidate.");
        return onlyViewer;
    }
}

public sealed record ViewerRoleAssignmentResult(Guid ProvisioningId, string State, bool Transitioned);
