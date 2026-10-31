namespace Sun.Security.Bootstrap;

/// <summary>
/// Fail-closed verification gate between Keycloak and PostgreSQL master activation.
/// The adapter must return the complete membership of the realm's master role.
/// </summary>
public sealed class MasterIdentityVerifier(
    MasterReservationStore reservations,
    KeycloakManagementClient keycloak)
{
    /// <summary>
    /// Reconcile an existing master identity. Never creates users, assigns roles,
    /// changes credentials or enables accounts.
    /// </summary>
    public async Task<MasterReservation> VerifyAndActivateAsync(
        string expectedUsername,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedUsername);

        var reservation = await reservations.ReserveAsync(cancellationToken);
        var user = await keycloak.FindUserByUsernameAsync(expectedUsername, cancellationToken)
            ?? throw new InvalidOperationException("Expected master identity does not exist in Keycloak.");

        if (!user.Enabled || string.IsNullOrWhiteSpace(user.Id))
            throw new InvalidOperationException("Master identity is disabled or has no subject identifier.");

        var members = await keycloak.GetMasterRoleMembersAsync(cancellationToken);
        if (members.Count != 1 ||
            !string.Equals(members[0].Id, user.Id, StringComparison.Ordinal) ||
            !members[0].Enabled)
            throw new InvalidOperationException("Keycloak must have exactly one enabled master role member matching the expected identity.");

        if (reservation.IsActive && !string.Equals(reservation.SubjectId, user.Id, StringComparison.Ordinal))
            throw new InvalidOperationException("Database master does not match the verified Keycloak subject.");

        return await reservations.ActivateVerifiedAsync(user.Id, cancellationToken);
    }
}
