namespace Sun.Security.Bootstrap;

/// <summary>
/// Safe first phase of master bootstrap: serialize, reserve and reconcile ownership.
/// Does not assign roles, set credentials, or enable accounts.
/// </summary>
public sealed class MasterProvisioningCoordinator(
    MasterProvisioningLock provisioningLock,
    MasterReservationStore reservations,
    KeycloakManagementClient keycloak)
{
    /// <summary>
    /// Enables the sole owned master identity after role assignment.
    /// Holds the deployment advisory lease across Keycloak checks and mutation.
    /// Database activation is a separate, ownership-verified reconciliation step.
    /// </summary>
    public async Task EnablePreparedMasterAsync(
        string username,
        string deploymentIdentifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(deploymentIdentifier);

        await using var lease = await provisioningLock.TryAcquireAsync(cancellationToken)
            ?? throw new InvalidOperationException("Another master provisioning operation is running.");

        var reservation = await reservations.ReserveAsync(cancellationToken);
        if (reservation.IsActive || reservation.SubjectId is not null)
            throw new InvalidOperationException("Master reservation is already active or bound.");

        var candidate = await keycloak.FindUserByUsernameAsync(username, cancellationToken)
            ?? throw new InvalidOperationException("Prepared master identity is missing.");
        var marker = MasterIdentityOwnership.ComputeMarker(deploymentIdentifier);
        if (string.IsNullOrWhiteSpace(candidate.Id) ||
            !string.Equals(candidate.Username, username, StringComparison.Ordinal) ||
            candidate.Attributes is null ||
            !candidate.Attributes.TryGetValue(MasterIdentityOwnership.AttributeName, out var values) ||
            values is null || values.Count != 1 ||
            !string.Equals(values[0], marker, StringComparison.Ordinal))
            throw new InvalidOperationException("Master identity ownership verification failed.");

        var members = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (members.Count != 1 ||
            !string.Equals(members[0].Id, candidate.Id, StringComparison.Ordinal))
            throw new InvalidOperationException("Expected identity must be the sole direct master role member.");

        if (!await keycloak.HasPasswordCredentialAsync(candidate.Id, cancellationToken))
            throw new InvalidOperationException("Master identity has no configured password credential.");

        // A previously completed PUT may have lost its response. Accept only an
        // already-enabled, still-owned candidate with matching sole membership.
        if (!candidate.Enabled)
        {
            if (members[0].Enabled)
                throw new InvalidOperationException("Master role membership state is inconsistent.");
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.EnableUserAsync(candidate.Id, cancellationToken);
        }

        var after = await keycloak.FindUserByUsernameAsync(username, cancellationToken)
            ?? throw new InvalidOperationException("Master identity disappeared during enablement.");
        var afterMembers = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (!after.Enabled || !string.Equals(after.Id, candidate.Id, StringComparison.Ordinal) ||
            after.Attributes is null ||
            !after.Attributes.TryGetValue(MasterIdentityOwnership.AttributeName, out var afterMarkers) ||
            afterMarkers is null || afterMarkers.Count != 1 ||
            !string.Equals(afterMarkers[0], marker, StringComparison.Ordinal) ||
            afterMembers.Count != 1 ||
            !string.Equals(afterMembers[0].Id, candidate.Id, StringComparison.Ordinal) ||
            !afterMembers[0].Enabled)
            throw new InvalidOperationException("Master enablement postconditions failed.");
    }

    /// <summary>
    /// Sets the initial credential only for an owned, disabled candidate while
    /// holding the deployment-wide provisioning lock. Never touches active users.
    /// </summary>
    public async Task SetPreparedInitialPasswordAsync(
        string username,
        string deploymentIdentifier,
        string initialPassword,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(deploymentIdentifier);
        ArgumentException.ThrowIfNullOrWhiteSpace(initialPassword);
        if (initialPassword.Length < 16)
            throw new ArgumentException("Initial password must be at least 16 characters.", nameof(initialPassword));

        await using var lease = await provisioningLock.TryAcquireAsync(cancellationToken)
            ?? throw new InvalidOperationException("Another master provisioning operation is running.");

        var reservation = await reservations.ReserveAsync(cancellationToken);
        if (reservation.IsActive)
            throw new InvalidOperationException("Cannot reset credentials after master activation.");

        var members = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (members.Count != 0)
            throw new InvalidOperationException("Master role already assigned; credential setup refused.");

        var user = await keycloak.FindUserByUsernameAsync(username, cancellationToken);
        var marker = MasterIdentityOwnership.ComputeMarker(deploymentIdentifier);
        if (user is null || user.Enabled || string.IsNullOrWhiteSpace(user.Id) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue(MasterIdentityOwnership.AttributeName, out var markers) ||
            markers is null || markers.Count != 1 ||
            !string.Equals(markers[0], marker, StringComparison.Ordinal))
            throw new InvalidOperationException("Identity is not an owned, disabled bootstrap candidate.");

        await lease.EnsureHeldAsync(cancellationToken);
        await keycloak.SetInitialPasswordAsync(user.Id, initialPassword, cancellationToken);
    }

    /// <summary>
    /// Grants the master realm role only to an owned, disabled candidate while
    /// holding the deployment provisioning lease. Never enables the account.
    /// </summary>
    public async Task AssignPreparedMasterRoleAsync(
        string username,
        string deploymentIdentifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(deploymentIdentifier);

        await using var lease = await provisioningLock.TryAcquireAsync(cancellationToken)
            ?? throw new InvalidOperationException("Another master provisioning operation is running.");

        var reservation = await reservations.ReserveAsync(cancellationToken);
        var candidate = await keycloak.FindUserByUsernameAsync(username, cancellationToken);
        var members = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        var decision = MasterRoleAssignmentPolicy.Evaluate(
            reservation, candidate, username,
            MasterIdentityOwnership.ComputeMarker(deploymentIdentifier), members);

        if (decision == MasterRoleAssignmentDecision.Reject)
            throw new InvalidOperationException("Master role assignment preconditions failed.");

        if (decision == MasterRoleAssignmentDecision.Eligible)
        {
            // An ambiguous remote response must be reconciled on the next run.
            // Never blindly retry the POST in this invocation.
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.AddMasterRoleMappingAsync(candidate!.Id, cancellationToken);
        }

        var after = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (after.Count != 1 ||
            !string.Equals(after[0].Id, candidate!.Id, StringComparison.Ordinal) ||
            after[0].Enabled)
            throw new InvalidOperationException("Master role assignment postcondition failed.");
    }

    public async Task<MasterProvisioningResult> PrepareAsync(
        string username,
        string email,
        string deploymentIdentifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(deploymentIdentifier);

        await using var lease = await provisioningLock.TryAcquireAsync(cancellationToken)
            ?? throw new InvalidOperationException("Another master provisioning operation is running.");

        var reservation = await reservations.ReserveAsync(cancellationToken);
        if (reservation.IsActive)
            throw new InvalidOperationException("Master is already active; use verified reconciliation, not preparation.");

        // Check before any Keycloak mutation. A pre-existing master role assignment
        // requires operator reconciliation rather than creating another candidate.
        var members = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (members.Count != 0)
            throw new InvalidOperationException("Master role is already assigned; manual reconciliation required.");

        var marker = MasterIdentityOwnership.ComputeMarker(deploymentIdentifier);
        var existing = await keycloak.FindUserByUsernameAsync(username, cancellationToken);
        if (existing is null)
        {
            // The create endpoint returns no stable ID. Always re-query after creation,
            // including when the response was lost; never blindly retry a failed POST.
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.CreateDisabledOwnedUserAsync(username, email, marker, cancellationToken);
            existing = await keycloak.FindUserByUsernameAsync(username, cancellationToken);
        }

        if (existing is null || existing.Enabled ||
            !string.Equals(existing.Username, username, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(existing.Id) ||
            existing.Attributes is null ||
            !existing.Attributes.TryGetValue(MasterIdentityOwnership.AttributeName, out var markers) ||
            markers is null || markers.Count != 1 ||
            !string.Equals(markers[0], marker, StringComparison.Ordinal))
            throw new InvalidOperationException("Existing identity is not a disabled, owned bootstrap identity.");

        // Recheck after the remote operation: role membership may have changed.
        members = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (members.Count != 0)
            throw new InvalidOperationException("Master role changed during preparation; manual reconciliation required.");

        return new MasterProvisioningResult("prepared-disabled", existing.Id);
    }
}

public sealed record MasterProvisioningResult(string State, string? SubjectId);
