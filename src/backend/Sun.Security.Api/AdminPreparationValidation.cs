using System.Net.Mail;
using System.Text.RegularExpressions;

namespace Sun.Security.Api;

/// <summary>Rejects ambiguous or malformed identifiers before Keycloak calls.</summary>
public static partial class AdminPreparationValidation
{
    [GeneratedRegex(@"\A[a-zA-Z0-9][a-zA-Z0-9._-]{2,63}\z", RegexOptions.CultureInvariant)]
    private static partial Regex UsernamePattern();

    public static bool IsValid(string? username, string? email)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(email) ||
            username != username.Trim() || email != email.Trim() ||
            !UsernamePattern().IsMatch(username) || email.Length > 254 ||
            email.Any(char.IsWhiteSpace))
            return false;

        return MailAddress.TryCreate(email, out var address) &&
            string.Equals(address.Address, email, StringComparison.OrdinalIgnoreCase) &&
            address.Host.Contains('.', StringComparison.Ordinal);
    }
}
