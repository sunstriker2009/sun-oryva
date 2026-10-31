namespace Sun.Security.Bootstrap;

/// <summary>
/// Runtime master authorization boundary. The caller must first validate the
/// token's signature, issuer, audience, lifetime and direct realm-role claim.
/// This gate additionally requires the token subject to equal the active
/// PostgreSQL master subject; it never trusts a role claim alone.
/// </summary>
public sealed class ActiveMasterAuthorization(MasterReservationStore reservations)
{
    public async Task<bool> IsActiveMasterSubjectAsync(
        string? validatedTokenSubject,
        bool hasValidatedMasterRole,
        CancellationToken cancellationToken = default)
    {
        if (!hasValidatedMasterRole || string.IsNullOrWhiteSpace(validatedTokenSubject))
            return false;

        // Database failures must propagate: callers must fail closed, not
        // silently fall back to token-only role authorization.
        var activeSubject = await reservations.GetActiveMasterSubjectAsync(cancellationToken);
        return !string.IsNullOrWhiteSpace(activeSubject) &&
            string.Equals(activeSubject, validatedTokenSubject, StringComparison.Ordinal);
    }
}
