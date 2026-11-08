using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sun.Security.Bootstrap;

static void RejectConfiguration(Action action)
{
    try { action(); }
    catch (ArgumentException) { return; }
    throw new Exception("Unsafe SMTP configuration was accepted.");
}

const string password = "ci-secret-not-for-delivery";
const string token = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
SmtpStartTlsInvitationTransport Make(int port) =>
    new("127.0.0.1", port, "ci-user", password, "oryva@example.invalid");

RejectConfiguration(() => new SmtpStartTlsInvitationTransport(
    "smtp://relay.example", 587, "ci-user", password, "oryva@example.invalid"));
RejectConfiguration(() => new SmtpStartTlsInvitationTransport(
    "relay.example", 465, "ci-user", password, "oryva@example.invalid"));
RejectConfiguration(() => new SmtpStartTlsInvitationTransport(
    "relay.example", 587, "", password, "oryva@example.invalid"));
RejectConfiguration(() => new SmtpStartTlsInvitationTransport(
    "relay.example", 587, "ci-user", "", "oryva@example.invalid"));
RejectConfiguration(() => new SmtpStartTlsInvitationTransport(
    "relay.example", 587, "ci-user", password, "Display <oryva@example.invalid>"));
RejectConfiguration(() => new SmtpStartTlsInvitationTransport(
    "relay.example", 587, "ci-user", password, "one@example.invalid,two@example.invalid"));

if (Make(587).ToString().Contains(password, StringComparison.Ordinal))
    throw new Exception("SMTP configuration string exposed a credential.");
try
{
    await Make(587).SendAsync("one@example.invalid,two@example.invalid", token, default);
    throw new Exception("Multiple recipients were accepted.");
}
catch (ViewerInvitationTransportException ex)
{
    if (ex.InnerException is not null || ex.ToString().Contains(token, StringComparison.Ordinal))
        throw new Exception("SMTP validation failure exposed invitation details.");
}
foreach (var malformed in new[] {
    "ci-sensitive-invitation-bearer",
    token + "\\r\\nBcc: attacker@example.invalid",
    token[..42] + "=",
    token[..42] + "+",
    token[..42] + "B"
})
{
    try
    {
        await Make(587).SendAsync("viewer@example.invalid", malformed, default);
        throw new Exception("Malformed invitation bearer was accepted.");
    }
    catch (ViewerInvitationTransportException ex)
    {
        if (ex.InnerException is not null || ex.ToString().Contains(malformed, StringComparison.Ordinal))
            throw new Exception("Malformed bearer failure leaked sensitive content.");
    }
}
Console.WriteLine("PASS malformed invitation bearers are rejected before SMTP");

Console.WriteLine("PASS SMTP configuration, single-recipient gate and redacted failures");

await AssertSmtpFailureAsync(advertiseStartTls: false);
Console.WriteLine("PASS SMTP relay without STARTTLS cannot receive credentials or invitation");
await AssertSmtpFailureAsync(advertiseStartTls: true);
Console.WriteLine("PASS untrusted STARTTLS certificate cannot receive credentials or invitation");

async Task AssertSmtpFailureAsync(bool advertiseStartTls)
{
    using var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
    var commands = new List<string>();
    var server = Task.Run(async () =>
    {
        using var peer = await listener.AcceptTcpClientAsync(timeout.Token);
        using var stream = peer.GetStream();
        using var reader = new StreamReader(stream, Encoding.ASCII, false, 1024, leaveOpen: true);
        using var writer = new StreamWriter(stream, Encoding.ASCII, 1024, leaveOpen: true)
        {
            NewLine = "\r\n",
            AutoFlush = true
        };
        await writer.WriteLineAsync("220 localhost ESMTP");
        var hello = await reader.ReadLineAsync(timeout.Token);
        if (hello is null || !hello.StartsWith("EHLO ", StringComparison.OrdinalIgnoreCase))
            throw new Exception("SMTP client did not negotiate EHLO.");
        commands.Add(hello);
        await writer.WriteLineAsync("250-localhost");
        if (advertiseStartTls)
            await writer.WriteLineAsync("250-STARTTLS");
        await writer.WriteLineAsync("250 AUTH PLAIN");

        var next = await reader.ReadLineAsync(timeout.Token);
        if (next is null) return;
        commands.Add(next);
        if (!advertiseStartTls || next != "STARTTLS") return;
        await writer.WriteLineAsync("220 Ready to start TLS");

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var untrusted = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(5));
        using var tls = new SslStream(stream, leaveInnerStreamOpen: true);
        try
        {
            await tls.AuthenticateAsServerAsync(untrusted, false,
                SslProtocols.Tls12 | SslProtocols.Tls13, false);
            using var tlsReader = new StreamReader(tls, Encoding.ASCII, false, 1024, leaveOpen: true);
            var afterTls = await tlsReader.ReadLineAsync(timeout.Token);
            if (afterTls is not null) commands.Add(afterTls);
        }
        catch (IOException) { /* Client correctly rejected untrusted TLS. */ }
        catch (AuthenticationException) { /* Client correctly rejected untrusted TLS. */ }
    }, timeout.Token);

    try
    {
        await Make(port).SendAsync("viewer@example.invalid", token, timeout.Token);
        throw new Exception("Unsecured or untrusted SMTP relay was accepted.");
    }
    catch (ViewerInvitationTransportException ex)
    {
        if (ex.InnerException is not null ||
            ex.ToString().Contains(password, StringComparison.Ordinal) ||
            ex.ToString().Contains(token, StringComparison.Ordinal) ||
            ex.ToString().Contains("viewer@example.invalid", StringComparison.Ordinal))
            throw new Exception("SMTP failure leaked sensitive transport details.");
    }
    await server;
    if (!commands[0].StartsWith("EHLO ", StringComparison.OrdinalIgnoreCase) ||
        (advertiseStartTls && !commands.Contains("STARTTLS")) ||
        commands.Any(c => c.StartsWith("AUTH ", StringComparison.OrdinalIgnoreCase) ||
                          c.StartsWith("MAIL ", StringComparison.OrdinalIgnoreCase) ||
                          c.StartsWith("RCPT ", StringComparison.OrdinalIgnoreCase) ||
                          c.StartsWith("DATA", StringComparison.OrdinalIgnoreCase)))
        throw new Exception("SMTP attempted authentication or mail before trusted STARTTLS.");
}
