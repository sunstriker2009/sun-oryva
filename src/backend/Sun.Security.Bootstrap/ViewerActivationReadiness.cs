namespace Sun.Security.Bootstrap;

/// <summary>
/// Read-only preflight for viewer activation. The API caller must be an active
/// master or database-active admin. A readiness result is point-in-time and
/// never authorizes a later Keycloak enablement without repeating every check.
/// </summary>
public sealed class ViewerActivationReadiness(
    ViewerAccountStore accounts,
    KeycloakManagementClient keycloak,
    ViewerProvisioningLock provisioningLock)
{
    public async Task<ViewerActivationReadinessResult?> CheckAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new ViewerProvisioningBusyException();
        var state = await accounts.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State != "role_assigned")
            return new(id, state.State, false, "role_not_assigned");

        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (!ViewerActivationReadinessRules.HasOwnedDisabledIdentity(state, user))
            return new(id, state.State, false, "identity_mismatch");

        var direct = await keycloak.GetDirectOryvaRolesAsync(user!.Id, cancellationToken);
        var effective = await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken);
        var hasPassword = await keycloak.HasPasswordCredentialAsync(user.Id, cancellationToken);
        await lease.EnsureHeldAsync(cancellationToken);
        return ViewerActivationReadinessRules.Evaluate(
            state, user, direct, effective, hasPassword);
    }
}

/// <summary>
/// Strict activation gates, independently testable without modifying Keycloak.
/// Missing metadata is never interpreted as successful verification.
/// </summary>
public static class ViewerActivationReadinessRules
{
    public static bool HasOwnedDisabledIdentity(ViewerAccountState state, KeycloakUser? user) =>
        user is not null &&
        !user.Enabled &&
        !string.IsNullOrWhiteSpace(user.Id) &&
        !string.IsNullOrWhiteSpace(state.KeycloakSubjectId) &&
        string.Equals(user.Id, state.KeycloakSubjectId, StringComparison.Ordinal) &&
        string.Equals(user.Username, state.Username, StringComparison.Ordinal) &&
        string.Equals(user.Email, state.Email, StringComparison.OrdinalIgnoreCase) &&
        user.Attributes is not null &&
        user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) &&
        markers.Count == 1 &&
        string.Equals(markers[0], state.Id.ToString("D"), StringComparison.Ordinal);

    public static ViewerActivationReadinessResult Evaluate(
        ViewerAccountState state, KeycloakUser? user,
        IReadOnlyList<string> directRoles, IReadOnlyList<string> effectiveRoles,
        bool hasPassword)
    {
        if (state.State != "role_assigned")
            return new(state.Id, state.State, false, "role_not_assigned");
        if (!HasOwnedDisabledIdentity(state, user))
            return new(state.Id, state.State, false, "identity_mismatch");
        if (directRoles.Count != 1 || directRoles[0] != "viewer" ||
            effectiveRoles.Count != 1 || effectiveRoles[0] != "viewer")
            return new(state.Id, state.State, false, "role_mismatch");
        if (!hasPassword)
            return new(state.Id, state.State, false, "password_missing");
        if (!user!.EmailVerified)
            return new(state.Id, state.State, false, "email_not_verified");
        if (user.RequiredActions is null || user.RequiredActions.Count != 0)
            return new(state.Id, state.State, false, "required_actions_pending");
        return new(state.Id, state.State, true, "ready_for_guarded_activation");
    }
}

public sealed record ViewerActivationReadinessResult(
    Guid ProvisioningId, string State, bool Ready, string Finding);
