using System.Security.Cryptography;
using System.Text;

namespace Sun.Security.Bootstrap;

/// <summary>
/// External 256-bit key material for internal invitation outbox encryption.
/// Keys must come from a secret manager, never source control or the database.
/// This primitive does not send mail or activate an identity.
/// </summary>
public sealed class ViewerInvitationOutboxCrypto
{
    private readonly byte[] key;
    public string KeyId { get; }

    public ViewerInvitationOutboxCrypto(string keyId, ReadOnlySpan<byte> keyMaterial)
    {
        if (string.IsNullOrEmpty(keyId) || keyId.Length > 64 ||
            keyId.Any(c => !((c >= 'a' && c <= 'z') ||
                             (c >= 'A' && c <= 'Z') ||
                             (c >= '0' && c <= '9') || c is '.' or '_' or '-')))
            throw new ArgumentException("Invalid outbox key identifier.", nameof(keyId));
        if (keyMaterial.Length != 32)
            throw new ArgumentException("AES-256-GCM requires a 32-byte key.", nameof(keyMaterial));
        KeyId = keyId;
        key = keyMaterial.ToArray();
    }

    private static byte[] AssociatedData(Guid challengeId, Guid viewerId,
        string recipientEmail, string keyId) =>
        Encoding.UTF8.GetBytes($"oryva-invitation-v1\n{challengeId:N}\n{viewerId:N}\n{recipientEmail}\n{keyId}");

    public ViewerInvitationEncryptedToken Encrypt(Guid challengeId, Guid viewerId,
        string recipientEmail, string token)
    {
        if (token.Length != 43)
            throw new ArgumentException("Expected a 256-bit URL-safe invitation token.", nameof(token));
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = Encoding.ASCII.GetBytes(token);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag,
                AssociatedData(challengeId, viewerId, recipientEmail, KeyId));
            return new ViewerInvitationEncryptedToken(KeyId, nonce, ciphertext, tag);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }

    /// <summary>
    /// Trusted delivery worker only. Never expose the returned bearer secret
    /// through HTTP, logs or telemetry. Caller must revalidate challenge state.
    /// </summary>
    public string Decrypt(Guid challengeId, Guid viewerId, string recipientEmail,
        ViewerInvitationEncryptedToken encrypted)
    {
        if (encrypted.KeyId != KeyId)
            throw new CryptographicException("Outbox encryption key identifier mismatch.");
        var plaintext = new byte[encrypted.Ciphertext.Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(encrypted.Nonce, encrypted.Ciphertext, encrypted.Tag,
                plaintext, AssociatedData(challengeId, viewerId, recipientEmail, KeyId));
            return Encoding.ASCII.GetString(plaintext);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}

/// <summary>Encrypted transport envelope; contains no plaintext bearer secret.</summary>
public sealed record ViewerInvitationEncryptedToken(
    string KeyId, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>Metadata-only issuance receipt; no bearer token is returned.</summary>
public sealed record ViewerInvitationQueuedReceipt(Guid Id, DateTime ExpiresAtUtc);
