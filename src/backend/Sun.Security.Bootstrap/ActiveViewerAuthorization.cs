namespace Sun.Security.Bootstrap;

/// <summary>
/// Requires a validated, exclusive viewer realm role and committed active
/// PostgreSQL subject on every request. Never caches a positive decision.
/// </summary>
public sealed class ActiveViewerAuthorization(ViewerAccountStore viewers)
{
    public Task<bool> IsActiveViewerSubjectAsync(
        string? validatedTokenSubject, bool hasValidatedViewerRole,
        CancellationToken cancellationToken = default)
    {
        if (!hasValidatedViewerRole || string.IsNullOrWhiteSpace(validatedTokenSubject))
            return Task.FromResult(false);
        return viewers.IsActiveViewerSubjectAsync(validatedTokenSubject, cancellationToken);
    }
}
