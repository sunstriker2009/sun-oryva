namespace Sun.Security.Bootstrap;

/// <summary>
/// Fail-closed viewer preparation. A reservation is committed before any
/// Keycloak request. Ambiguous responses are recovered by read-only identity
/// verification, never by adopting or recreating an existing user.
/// No viewer role, credentials, or enablement are granted here.
/// </summary>
public sealed class ViewerPreparationCoordinator(
    ViewerAccountStore accounts, KeycloakManagementClient keycloak)
{
    public async Task<ViewerAccountState> PrepareAsync(
        string username, string email, string actorSubject, string actorRole,
        CancellationToken cancellationToken = default)
    {
        var reservation = await accounts.ReserveAsync(
            username, email, actorSubject, actorRole, cancellationToken);
        // If Keycloak times out after creating the user, keep the reservation.
        // The caller can explicitly reconcile it using its opaque ID.
        await keycloak.CreateDisabledViewerCandidateAsync(
            username, email, reservation.Id, cancellationToken);
        return await RecoverAsync(reservation.Id, cancellationToken)
            ?? throw new InvalidOperationException("Viewer reservation disappeared.");
    }

    /// <summary>
    /// Inspects an existing reservation only. Never creates or enables a user.
    /// Conditional SQL transition prevents two callers binding different subjects.
    /// </summary>
    public async Task<ViewerAccountState?> RecoverAsync(
        Guid id, CancellationToken cancellationToken = default)
    {
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
            await accounts.MarkPreparedAsync(id, user.Id, cancellationToken);
        return await accounts.GetAsync(id, cancellationToken)
            ?? throw new InvalidOperationException("Viewer reservation disappeared.");
    }
}
