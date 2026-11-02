using System.Net;
using System.Net.Mail;

namespace Sun.Security.Bootstrap;

/// <summary>
/// Opt-in SMTP transport for a separately approved dispatcher. It requires
/// authenticated STARTTLS and the platform's normal certificate validation.
/// It is intentionally not registered in DI or started by the application.
/// </summary>
public sealed class SmtpStartTlsInvitationTransport : IViewerInvitationMailTransport
{
    private readonly string host;
    private readonly int port;
    private readonly string username;
    private readonly string password;
    private readonly string senderEmail;

    /// <summary>
    /// All values must originate from trusted deployment configuration. Supply
    /// the password from a runtime secret manager, never from source control.
    /// Port 465 (implicit TLS) is deliberately unsupported by SmtpClient.
    /// </summary>
    public SmtpStartTlsInvitationTransport(
        string host, int port, string username, string password, string senderEmail)
    {
        if (string.IsNullOrWhiteSpace(host) || host != host.Trim() ||
            host.Any(char.IsWhiteSpace) ||
            Uri.CheckHostName(host) is not (UriHostNameType.Dns or UriHostNameType.IPv4))
            throw new ArgumentException("A plain SMTP DNS name or IPv4 address is required.", nameof(host));
        if (port is < 1 or > 65535 or 465)
            throw new ArgumentOutOfRangeException(nameof(port), "Use a STARTTLS port (normally 587), not implicit TLS.");
        if (string.IsNullOrWhiteSpace(username) || username.Any(char.IsControl))
            throw new ArgumentException("An explicit SMTP username is required.", nameof(username));
        if (string.IsNullOrEmpty(password))
            throw new ArgumentException("An explicit SMTP credential is required.", nameof(password));

        this.host = host;
        this.port = port;
        this.username = username;
        this.password = password;
        this.senderEmail = RequireSingleMailbox(senderEmail);
    }

    public async Task SendAsync(
        string recipientEmail, string bearerCode, CancellationToken cancellationToken)
    {
        // Reject multi-recipient strings and display names: a single invitation
        // must never be delivered to an extra address from malformed stored data.
        try
        {
            var recipient = RequireSingleMailbox(recipientEmail);
            if (string.IsNullOrWhiteSpace(bearerCode))
                throw new ArgumentException("Missing invitation code.", nameof(bearerCode));

            using var message = new MailMessage(senderEmail, recipient)
            {
                Subject = "ORYVA by Sun invitation code",
                Body = "Your ORYVA one-time invitation code: " + bearerCode +
                       "\nThis code expires 15 minutes after issuance. " +
                       "Do not forward it. Enrollment is not yet available.",
                IsBodyHtml = false
            };
            using var client = new SmtpClient(host, port)
            {
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(username, password),
                EnableSsl = true, // Requires STARTTLS; no plaintext fallback.
                Timeout = 10_000
            };
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            bounded.CancelAfter(TimeSpan.FromSeconds(10));
            await client.SendMailAsync(message, bounded.Token);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            // Never propagate SMTP server responses, message content, recipient
            // addresses or credentials via an exception or inner exception.
            throw new ViewerInvitationTransportException();
        }
    }

    public override string ToString() => "ORYVA STARTTLS SMTP transport (credentials redacted)";

    private static string RequireSingleMailbox(string email)
    {
        if (string.IsNullOrWhiteSpace(email) || email != email.Trim() ||
            email.Any(char.IsControl) || email.Contains(',') || email.Contains(';') ||
            !MailAddress.TryCreate(email, out var address) ||
            !string.Equals(address.Address, email, StringComparison.Ordinal) ||
            !string.IsNullOrEmpty(address.DisplayName))
            throw new ArgumentException("A single plain mailbox address is required.", nameof(email));
        return address.Address;
    }
}
