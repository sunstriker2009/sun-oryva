namespace Sun.Security.Bootstrap;

/// <summary>
/// Read-only, master-authorized preflight for a future admin activation flow.
/// Readiness is point-in-time and NEVER authorizes enablement on its own.
/// </summary>
public sealed class AdminActivationReadiness(
    AdminProvisioningStore reservations,
    KeycloakManagementClient keycloak,
    AdminProvisioningLock provisioningLock)
{
    public async Task<AdminActivationReadinessResult?> CheckAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        // Serialize with ORYVA role assignment and recovery to avoid observing
        // intermediate database states while a provisioning writer is active.
        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new AdminProvisioningBusyException();
        var state = await reservations.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State != "role_assigned")
            return new(id, state.State, false, "role_not_assigned");

        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (!AdminActivationReadinessRules.HasOwnedDisabledIdentity(state, user))
            return new(id, state.State, false, "identity_mismatch");

        var direct = await keycloak.GetDirectOryvaRolesAsync(user!.Id, cancellationToken);
        var effective = await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken);
        var hasPassword = await keycloak.HasPasswordCredentialAsync(user.Id, cancellationToken);
        await lease.EnsureHeldAsync(cancellationToken);
        return AdminActivationReadinessRules.Evaluate(
            state, user, direct, effective, hasPassword);
    }
}

/// <summary>
/// Pure fail-closed rules, also exercised with synthetic positive/negative
/// identity representations. No credentials or email verification are modified.
/// </summary>
public static class AdminActivationReadinessRules
{
    public static bool HasOwnedDisabledIdentity(
        AdminProvisioningState state, KeycloakUser? user) =>
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

    public static AdminActivationReadinessResult Evaluate(
        AdminProvisioningState state, KeycloakUser? user,
        IReadOnlyList<string> directRoles, IReadOnlyList<string> effectiveRoles,
        bool hasPassword)
    {
        if (state.State != "role_assigned")
            return new(state.Id, state.State, false, "role_not_assigned");
        if (!HasOwnedDisabledIdentity(state, user))
            return new(state.Id, state.State, false, "identity_mismatch");
        if (directRoles.Count != 1 || directRoles[0] != "admin" ||
            effectiveRoles.Count != 1 || effectiveRoles[0] != "admin")
            return new(state.Id, state.State, false, "role_mismatch");
        if (!hasPassword)
            return new(state.Id, state.State, false, "password_missing");
        if (!user!.EmailVerified)
            return new(state.Id, state.State, false, "email_not_verified");
        // Missing requiredActions metadata is NOT equivalent to an empty list.
        if (user.RequiredActions is null || user.RequiredActions.Count != 0)
            return new(state.Id, state.State, false, "required_actions_pending");
        return new(state.Id, state.State, true, "ready_for_guarded_activation");
    }
}

public sealed record AdminActivationReadinessResult(
    Guid ProvisioningId, string State, bool Ready, string Finding);
