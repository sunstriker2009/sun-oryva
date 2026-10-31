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

        await keycloak.SetInitialPasswordAsync(user.Id, initialPassword, cancellationToken);
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
