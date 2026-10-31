using System.Net;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Prevents redirects from silently forwarding management requests or credentials.
/// Register as the primary HttpClient handler for the Keycloak management adapter.
/// </summary>
public static class KeycloakHttpClientFactory
{
    public static HttpClient Create()
    {
        return new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false
        });
    }

    public static void EnsureNoRedirect(HttpResponseMessage response)
    {
        if ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400)
            throw new HttpRequestException(
                "Keycloak management endpoint returned a redirect; refusing to follow it.",
                null, response.StatusCode);
    }
}
