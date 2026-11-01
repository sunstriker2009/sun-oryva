namespace Sun.Security.Bootstrap;

/// <summary>
/// Guarded activation of a previously provisioned viewer. The HTTP caller must
/// be an active master or database-active admin; the authenticated actor is
/// recorded on both durable transitions. No password or verification flags are set.
/// </summary>
public sealed class ViewerActivationCoordinator(
    ViewerAccountStore accounts,
    KeycloakManagementClient keycloak,
    ViewerProvisioningLock provisioningLock)
{
    public async Task<ViewerActivationResult?> ActivateAsync(
        Guid id, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(actorSubject);
        if (actorRole is not ("master" or "admin"))
            throw new ArgumentException("Only an active master or admin can activate viewers.",
                nameof(actorRole));

        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new ViewerProvisioningBusyException();
        var state = await accounts.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("role_assigned" or "activation_pending" or "active"))
            throw new InvalidOperationException("Viewer reservation is not eligible for activation.");

        if (state.State == "active")
        {
            // An idempotent response must still reject drift in Keycloak.
            await RequireVerifiedAsync(state, enabled: true, cancellationToken);
            return new ViewerActivationResult(id, "active", false);
        }

        if (state.State == "role_assigned")
        {
            // Never adopt an externally enabled identity without our own
            // committed activation intent. Recheck every readiness gate under
            // the same lease that guards role assignment and preparation.
            await RequireVerifiedAsync(state, enabled: false, cancellationToken);
            await lease.EnsureHeldAsync(cancellationToken);
            await accounts.MarkActivationPendingAsync(
                id, state.KeycloakSubjectId!, actorSubject, actorRole, cancellationToken);
            state = state with { State = "activation_pending" };
        }

        // A lost Keycloak response may have enabled the account. Reconcile
        // only when the durable intent exists and all identity/role/credential
        // gates still hold. 'activation_pending' never authorizes viewer APIs.
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken)
            ?? throw new InvalidOperationException("Keycloak viewer candidate disappeared.");
        if (user.Enabled)
        {
            await RequireVerifiedAsync(state, enabled: true, cancellationToken);
        }
        else
        {
            await RequireVerifiedAsync(state, enabled: false, cancellationToken);
            await lease.EnsureHeldAsync(cancellationToken);
            await keycloak.EnableUserAsync(state.KeycloakSubjectId!, cancellationToken);
            // A successful HTTP response is not evidence of enablement.
            await RequireVerifiedAsync(state, enabled: true, cancellationToken);
        }

        await lease.EnsureHeldAsync(cancellationToken);
        await accounts.MarkActivatedAsync(
            id, state.KeycloakSubjectId!, actorSubject, actorRole, cancellationToken);
        return new ViewerActivationResult(id, "active", true);
    }

    private async Task RequireVerifiedAsync(
        ViewerAccountState state, bool enabled, CancellationToken cancellationToken)
    {
        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null || user.Enabled != enabled)
            throw new InvalidOperationException("Viewer activation identity state mismatch.");

        var direct = await keycloak.GetDirectOryvaRolesAsync(user.Id, cancellationToken);
        var effective = await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken);
        var hasPassword = await keycloak.HasPasswordCredentialAsync(user.Id, cancellationToken);
        // The preflight rules require a disabled role_assigned candidate.
        // Normalize ONLY those two expected transition fields after checking
        // actual Keycloak enabled state; preserve all ownership and security gates.
        var readiness = ViewerActivationReadinessRules.Evaluate(
            state with { State = "role_assigned" },
            user with { Enabled = false }, direct, effective, hasPassword);
        if (!readiness.Ready)
            throw new InvalidOperationException("Viewer activation rejected: " + readiness.Finding);
    }
}

public sealed record ViewerActivationResult(
    Guid ProvisioningId, string State, bool Transitioned);
