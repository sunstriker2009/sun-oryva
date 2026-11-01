namespace Sun.Security.Bootstrap;

/// <summary>
/// Master-authorized orchestration is enforced by the HTTP endpoint. This coordinator
/// serializes ORYVA writers, verifies Keycloak ownership and assigns only the admin
/// role to a disabled, uncredentialed identity. It never enables an account.
/// </summary>
public sealed class AdminRoleAssignmentCoordinator(
    AdminProvisioningStore reservations, KeycloakManagementClient keycloak,
    AdminProvisioningLock provisioningLock)
{
    public async Task<AdminRoleAssignmentResult?> AssignAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new AdminProvisioningBusyException();
        var state = await reservations.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("prepared" or "role_assignment_pending" or "role_assigned"))
            throw new InvalidOperationException("Admin reservation is not prepared for role assignment.");

        var hasAdmin = await VerifyDisabledOwnedCandidateAsync(state, cancellationToken);
        if (state.State == "role_assigned")
        {
            if (!hasAdmin)
                throw new InvalidOperationException("Persisted admin role no longer matches Keycloak.");
            return new AdminRoleAssignmentResult(id, "role_assigned", false);
        }
        if (state.State == "prepared")
        {
            if (hasAdmin)
                throw new InvalidOperationException("Unexpected pre-existing admin role.");
            await lease.EnsureHeldAsync(cancellationToken);
            // Durable intent precedes the external mutation. A lost response leaves
            // role_assignment_pending for explicit verification/retry.
            await reservations.MarkRoleAssignmentPendingAsync(id, state.KeycloakSubjectId!, cancellationToken);
            state = state with { State = "role_assignment_pending" };
        }

        if (!hasAdmin)
        {
            // Revalidate identity, disabled status, credential absence and all ORYVA
            // role mappings immediately before granting a role.
            if (await VerifyDisabledOwnedCandidateAsync(state, cancellationToken))
                throw new InvalidOperationException("Role mapping changed during assignment.");
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.AddAdminRoleMappingAsync(state.KeycloakSubjectId!, cancellationToken);
        }

        // An ambiguous Keycloak response is never interpreted as success. The
        // role must be observed directly and effectively before the DB transition.
        if (!await VerifyDisabledOwnedCandidateAsync(state, cancellationToken))
            throw new InvalidOperationException("Keycloak admin role was not verified.");
        await lease.EnsureHeldAsync(cancellationToken);
        await reservations.MarkRoleAssignedAsync(id, state.KeycloakSubjectId!, cancellationToken);
        return new AdminRoleAssignmentResult(id, "role_assigned", true);
    }

    private async Task<bool> VerifyDisabledOwnedCandidateAsync(
        AdminProvisioningState state, CancellationToken cancellationToken)
    {
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null || user.Enabled ||
            string.IsNullOrWhiteSpace(state.KeycloakSubjectId) ||
            !string.Equals(user.Id, state.KeycloakSubjectId, StringComparison.Ordinal) ||
            !string.Equals(user.Username, state.Username, StringComparison.Ordinal) ||
            !string.Equals(user.Email, state.Email, StringComparison.OrdinalIgnoreCase) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
            markers.Count != 1 ||
            !string.Equals(markers[0], state.Id.ToString("D"), StringComparison.Ordinal))
            throw new InvalidOperationException("Admin candidate ownership or disabled state mismatch.");

        if (await keycloak.HasPasswordCredentialAsync(user.Id, cancellationToken))
            throw new InvalidOperationException("Admin candidate already has password credentials.");

        var direct = await keycloak.GetDirectOryvaRolesAsync(user.Id, cancellationToken);
        var effective = await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken);
        var noRole = direct.Count == 0 && effective.Count == 0;
        var onlyAdmin = direct.Count == 1 && direct[0] == "admin" &&
                        effective.Count == 1 && effective[0] == "admin";
        if (!noRole && !onlyAdmin)
            throw new InvalidOperationException("Conflicting ORYVA roles on admin candidate.");
        return onlyAdmin;
    }
}

public sealed record AdminRoleAssignmentResult(
    Guid ProvisioningId, string State, bool Transitioned);
