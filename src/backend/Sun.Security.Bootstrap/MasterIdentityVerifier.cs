namespace Sun.Security.Bootstrap;

/// <summary>
/// Fail-closed verification gate between Keycloak and PostgreSQL master activation.
/// The adapter must return the complete membership of the realm's master role.
/// </summary>
public sealed class MasterIdentityVerifier(
    MasterReservationStore reservations,
    KeycloakManagementClient keycloak,
    MasterProvisioningLock provisioningLock)
{
    /// <summary>
    /// Verifies the deployment ownership marker and exactly one enabled master
    /// before recording activation. Holds the deployment-wide provisioning lease.
    /// </summary>
    public async Task<MasterReservation> VerifyAndActivateAsync(
        string expectedUsername,
        string deploymentIdentifier,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedUsername);
        ArgumentException.ThrowIfNullOrWhiteSpace(deploymentIdentifier);

        await using var lease = await provisioningLock.TryAcquireAsync(cancellationToken)
            ?? throw new InvalidOperationException("Another master provisioning operation is running.");

        var reservation = await reservations.ReserveAsync(cancellationToken);
        var user = await keycloak.FindUserByUsernameAsync(expectedUsername, cancellationToken)
            ?? throw new InvalidOperationException("Expected master identity is missing.");
        var marker = MasterIdentityOwnership.ComputeMarker(deploymentIdentifier);
        if (!user.Enabled || string.IsNullOrWhiteSpace(user.Id) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue(MasterIdentityOwnership.AttributeName, out var values) ||
            values is null || values.Count != 1 ||
            !string.Equals(values[0], marker, StringComparison.Ordinal))
            throw new InvalidOperationException("Enabled master identity lacks expected ownership marker.");

        var members = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (members.Count != 1 ||
            !string.Equals(members[0].Id, user.Id, StringComparison.Ordinal) ||
            !members[0].Enabled)
            throw new InvalidOperationException("Expected identity must be the sole enabled master role member.");

        if (reservation.IsActive &&
            !string.Equals(reservation.SubjectId, user.Id, StringComparison.Ordinal))
            throw new InvalidOperationException("Database master subject differs from Keycloak.");

        await lease.EnsureHeldAsync(cancellationToken);
        return await reservations.ActivateVerifiedAsync(user.Id, cancellationToken);
    }
}
