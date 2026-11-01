namespace Sun.Security.Bootstrap;

/// <summary>
/// Runtime admin authorization boundary. The caller must validate the JWT,
/// including issuer, audience, signature, lifetime and the exclusive admin
/// realm role. A role alone is never sufficient.
/// </summary>
public sealed class ActiveAdminAuthorization(AdminProvisioningStore reservations)
{
    public Task<bool> IsActiveAdminSubjectAsync(
        string? validatedTokenSubject, bool hasValidatedAdminRole,
        CancellationToken cancellationToken = default)
    {
        if (!hasValidatedAdminRole || string.IsNullOrWhiteSpace(validatedTokenSubject))
            return Task.FromResult(false);
        return reservations.IsActiveAdminSubjectAsync(validatedTokenSubject, cancellationToken);
    }
}
