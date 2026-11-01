namespace Sun.Security.Bootstrap;

/// <summary>
/// Master-authorized endpoint orchestrates activation under a cross-instance lease.
/// Durable intent precedes Keycloak enablement; ambiguous responses remain pending.
/// No credentials or email-verification flags are set by this coordinator.
/// </summary>
public sealed class AdminActivationCoordinator(
    AdminProvisioningStore reservations,
    KeycloakManagementClient keycloak,
    AdminProvisioningLock provisioningLock)
{
    public async Task<AdminActivationResult?> ActivateAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new AdminProvisioningBusyException();
        var state = await reservations.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("role_assigned" or "activation_pending" or "active"))
            throw new InvalidOperationException("Admin reservation is not eligible for activation.");

        if (state.State == "active")
        {
            await RequireVerifiedAsync(state, enabled: true, cancellationToken);
            return new AdminActivationResult(id, "active", false);
        }

        if (state.State == "role_assigned")
        {
            // Never adopt an already-enabled identity without our durable intent.
            await RequireVerifiedAsync(state, enabled: false, cancellationToken);
            await lease.EnsureHeldAsync(cancellationToken);
            await reservations.MarkActivationPendingAsync(
                id, state.KeycloakSubjectId!, cancellationToken);
            state = state with { State = "activation_pending" };
        }

        // If Keycloak completed a previous request but the response was lost,
        // verify every property before reconciling the pending reservation.
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null)
            throw new InvalidOperationException("Keycloak admin candidate disappeared.");
        if (user.Enabled)
        {
            await RequireVerifiedAsync(state, enabled: true, cancellationToken);
        }
        else
        {
            await RequireVerifiedAsync(state, enabled: false, cancellationToken);
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.EnableUserAsync(state.KeycloakSubjectId!, cancellationToken);
            // A successful HTTP response is not proof of enablement.
            await RequireVerifiedAsync(state, enabled: true, cancellationToken);
        }

        await lease.EnsureHeldAsync(cancellationToken);
        await reservations.MarkActivatedAsync(id, state.KeycloakSubjectId!, cancellationToken);
        return new AdminActivationResult(id, "active", true);
    }

    private async Task RequireVerifiedAsync(
        AdminProvisioningState state, bool enabled, CancellationToken cancellationToken)
    {
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null || user.Enabled != enabled)
            throw new InvalidOperationException("Admin activation identity state mismatch.");

        var direct = await keycloak.GetDirectOryvaRolesAsync(user.Id, cancellationToken);
        var effective = await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken);
        var password = await keycloak.HasPasswordCredentialAsync(user.Id, cancellationToken);
        // Reuse the strict readiness rules, replacing only the expected
        // persisted and enabled states for this verified activation transition.
        var normalized = state with { State = "role_assigned" };
        var readiness = AdminActivationReadinessRules.Evaluate(
            normalized, user with { Enabled = false }, direct, effective, password);
        if (!readiness.Ready)
            throw new InvalidOperationException(
                "Admin activation rejected: " + readiness.Finding);
    }
}

public sealed record AdminActivationResult(
    Guid ProvisioningId, string State, bool Transitioned);
