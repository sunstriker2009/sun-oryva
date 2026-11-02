using Npgsql;

namespace Sun.Security.Bootstrap;

public sealed class ViewerInvitationOutboxHealthStore(NpgsqlDataSource dataSource)
{
    public async Task<long> CountPendingAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await dataSource.OpenConnectionAsync(cancellationToken);
        await using var command = new NpgsqlCommand("SELECT count(*) FROM oryva.viewer_invitation_outbox WHERE state = 'pending';", connection);
        return (long)(await command.ExecuteScalarAsync(cancellationToken) ?? 0L);
    }
}
