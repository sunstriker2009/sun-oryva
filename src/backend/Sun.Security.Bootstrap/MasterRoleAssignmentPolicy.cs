namespace Sun.Security.Bootstrap;

/// <summary>
/// Pure, fail-closed decision logic for a proposed master role assignment.
/// This class performs no Keycloak mutation.
/// </summary>
public static class MasterRoleAssignmentPolicy
{
    public static MasterRoleAssignmentDecision Evaluate(
        MasterReservation reservation,
        KeycloakUser? candidate,
        string expectedUsername,
        string expectedOwnershipMarker,
        IReadOnlyList<KeycloakUser> roleMembers)
    {
        ArgumentNullException.ThrowIfNull(reservation);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedUsername);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedOwnershipMarker);
        ArgumentNullException.ThrowIfNull(roleMembers);

        if (reservation.State != "pending" || reservation.SubjectId is not null ||
            candidate is null || candidate.Enabled ||
            string.IsNullOrWhiteSpace(candidate.Id) ||
            !string.Equals(candidate.Username, expectedUsername, StringComparison.Ordinal) ||
            candidate.Attributes is null ||
            !candidate.Attributes.TryGetValue(MasterIdentityOwnership.AttributeName, out var markers) ||
            markers is null || markers.Count != 1 ||
            !string.Equals(markers[0], expectedOwnershipMarker, StringComparison.Ordinal))
            return MasterRoleAssignmentDecision.Reject;

        if (roleMembers.Count == 0)
            return MasterRoleAssignmentDecision.Eligible;

        return roleMembers.Count == 1 &&
               string.Equals(roleMembers[0].Id, candidate.Id, StringComparison.Ordinal) &&
               !roleMembers[0].Enabled
            ? MasterRoleAssignmentDecision.AlreadyAssigned
            : MasterRoleAssignmentDecision.Reject;
    }
}

public enum MasterRoleAssignmentDecision
{
    Reject,
    Eligible,
    AlreadyAssigned
}
