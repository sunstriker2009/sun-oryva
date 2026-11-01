using Npgsql;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Read-only viewer authorization boundary. Never trusts Keycloak role alone.
/// No viewer activation or provisioning mutation is exposed by this class.
/// </summary>
public sealed class ViewerAccountStore(NpgsqlDataSource dataSource)
{
    public async Task<bool> IsActiveViewerSubjectAsync(
        string? subjectId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(subjectId)) return false;
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("""
            SELECT EXISTS (
                SELECT 1 FROM oryva.viewer_accounts
                WHERE keycloak_subject_id = @subject AND state = 'active'
            );
            """, connection);
        command.Parameters.AddWithValue("subject", subjectId);
        return (bool)(await command.ExecuteScalarAsync(cancellationToken)
            ?? throw new InvalidOperationException("Viewer authorization query returned no result."));
    }
}
