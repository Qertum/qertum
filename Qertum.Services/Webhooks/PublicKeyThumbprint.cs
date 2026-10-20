using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Qertum.Services.Webhooks;

/// <summary>
/// Names a certificate's public key for <see cref="WebhookEventFamily.KeyAccess"/> events without
/// disclosing the certificate itself.
/// </summary>
internal static class PublicKeyThumbprint
{
    /// <summary>
    /// Lowercase hex SHA-256 over the certificate's DER <c>SubjectPublicKeyInfo</c>, or null when
    /// <paramref name="certificatePem"/> is absent or unparseable.
    /// </summary>
    /// <remarks>
    /// SHA-256 over the SPKI rather than the certificate's SubjectKeyIdentifier extension, which is
    /// SHA-1 by RFC 5280 convention, and rather than the certificate thumbprint, so the value stays
    /// stable across a renewal that reuses the key.
    /// </remarks>
    public static string? FromCertificatePem(string? certificatePem)
    {
        if (string.IsNullOrWhiteSpace(certificatePem)) return null;

        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            var spki = certificate.PublicKey.ExportSubjectPublicKeyInfo();
            return Convert.ToHexString(SHA256.HashData(spki)).ToLowerInvariant();
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or FormatException)
        {
            // A key that left the system still deserves an event, even unnamed.
            return null;
        }
    }
}
