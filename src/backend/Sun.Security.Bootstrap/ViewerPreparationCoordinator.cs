namespace Sun.Security.Bootstrap;

/// <summary>
/// Fail-closed viewer preparation. A reservation is committed before any
/// Keycloak request. Ambiguous responses are recovered by read-only identity
/// verification, never by adopting or recreating an existing user.
/// No viewer role, credentials, or enablement are granted here.
/// </summary>
public sealed class ViewerPreparationCoordinator(
    ViewerAccountStore accounts, KeycloakManagementClient keycloak,
    ViewerProvisioningLock provisioningLock)
{
    public async Task<ViewerAccountState> PrepareAsync(
        string username, string email, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default)
    {
        var reservation = await accounts.ReserveAsync(
            username, email, actorSubject, actorRole, cancellationToken);
        // If Keycloak times out after creating the user, keep the reservation.
        // The caller can explicitly reconcile it using its opaque ID.
        try
        {
            await keycloak.CreateDisabledViewerCandidateAsync(
                username, email, reservation.Id, cancellationToken);
            return await RecoverAsync(reservation.Id, cancellationToken)
                ?? throw new InvalidOperationException("Viewer reservation disappeared.");
        }
        catch (Exception error) when (error is not OperationCanceledException)
        {
            // The external write may have succeeded despite a lost response.
            // Surface the durable ID; never retry creation or silently adopt.
            throw new ViewerPreparationPendingException(reservation.Id, error);
        }
    }

    /// <summary>
    /// Inspects an existing reservation only. Never creates or enables a user.
    /// Conditional SQL transition prevents two callers binding different subjects.
    /// </summary>
    public async Task<ViewerAccountState?> RecoverAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
        await using var lease = await provisioningLock.TryAcquireAsync(id, cancellationToken)
            ?? throw new ViewerProvisioningBusyException();
        var state = await accounts.GetAsync(id, cancellationToken);
        if (state is null) return null;
        if (state.State is not ("reserved" or "prepared"))
            throw new InvalidOperationException("Viewer reservation is not recoverable.");

        var user = await keycloak.FindProvisionedUserAsync(state.Username, cancellationToken);
        if (user is null || user.Enabled || user.EmailVerified ||
            string.IsNullOrWhiteSpace(user.Id) ||
            !string.Equals(user.Username, state.Username, StringComparison.Ordinal) ||
            !string.Equals(user.Email, state.Email, StringComparison.OrdinalIgnoreCase) ||
            user.Attributes is null ||
            !user.Attributes.TryGetValue("oryva.provisioning.id", out var markers) ||
            markers.Count != 1 ||
            !string.Equals(markers[0], id.ToString("D"), StringComparison.Ordinal) ||
            (state.KeycloakSubjectId is not null &&
             !string.Equals(state.KeycloakSubjectId, user.Id, StringComparison.Ordinal)))
            throw new InvalidOperationException("Viewer Keycloak ownership verification failed.");

        if ((await keycloak.GetDirectOryvaRolesAsync(user.Id, cancellationToken)).Count != 0 ||
            (await keycloak.GetEffectiveOryvaRolesAsync(user.Id, cancellationToken)).Count != 0 ||
            await keycloak.HasPasswordCredentialAsync(user.Id, cancellationToken))
            throw new InvalidOperationException("Viewer candidate already has roles or credentials.");

        if (state.State == "reserved")
        {
            await lease.EnsureHeldAsync(cancellationToken);
            await accounts.MarkPreparedAsync(id, user.Id, cancellationToken);
        }
        var updated = await accounts.GetAsync(id, cancellationToken)
            ?? throw new InvalidOperationException("Viewer reservation disappeared.");
        if (updated.State != "prepared" ||
            !string.Equals(updated.KeycloakSubjectId, user.Id, StringComparison.Ordinal))
            throw new InvalidOperationException("Viewer preparation state changed during recovery.");
        return updated;
    }
}

public sealed class ViewerPreparationPendingException : InvalidOperationException
{
    public Guid ProvisioningId { get; }

    public ViewerPreparationPendingException(Guid provisioningId, Exception inner)
        : base("Viewer preparation is incomplete; explicit reconciliation required.", inner)
    {
        ProvisioningId = provisioningId;
    }
}
