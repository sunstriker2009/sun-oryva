using System.Security.Cryptography;
using System.Text;

namespace Sun.Security.Bootstrap;

/// <summary>Non-secret stable marker for identifying an ORYVA-managed bootstrap identity.</summary>
public static class MasterIdentityOwnership
{
    public const string AttributeName = "oryva.bootstrap.owner";

    /// <summary>Derives a deterministic marker from a deployment-scoped secret identifier.
    /// Never use the bootstrap password or service-account secret as input.</summary>
    public static string ComputeMarker(string deploymentIdentifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deploymentIdentifier);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes("oryva/master/v1/" + deploymentIdentifier));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
