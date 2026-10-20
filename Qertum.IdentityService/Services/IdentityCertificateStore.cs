using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Qertum.ServiceDefaults.Secrets;

namespace Qertum.IdentityService.Services;

/// <summary>
/// Owns the identity provider's own signing and encryption certificates on disk, and rotates
/// them before they expire.
/// </summary>
/// <remarks>
/// The previous implementation created each certificate once, guarded by <c>File.Exists</c>, and
/// never looked at it again. Because the file kept existing after the certificate stopped being
/// valid, expiry was a hard stop that could only be cleared by deleting the file by hand — which
/// replaces the key with no overlap and invalidates every token in flight.
///
/// Rotation here is additive. A new certificate is created once the newest one is within
/// <c>renewBefore</c> of expiry, and every still-valid certificate stays registered, so the
/// retiring key remains in the JWKS document (and available for decryption) until it actually
/// expires. Tokens issued under it keep validating for the whole overlap window.
/// </remarks>
internal static class IdentityCertificateStore
{
    /// <summary>Role name for the token-signing certificate.</summary>
    public const string SigningRole = "signing";

    /// <summary>Role name for the token-encryption certificate.</summary>
    public const string EncryptionRole = "encryption";

    /// <summary>
    /// Returns the usable certificates for <paramref name="role"/>, creating one if none is
    /// valid far enough into the future. Ordered newest expiry first, which is the order
    /// OpenIddict picks a signing credential from.
    /// </summary>
    /// <param name="keysDirectory">Directory holding the PFX files. Created if absent.</param>
    /// <param name="role">Either <see cref="SigningRole"/> or <see cref="EncryptionRole"/>.</param>
    /// <param name="subject">Subject DN for a newly created certificate.</param>
    /// <param name="lifetime">Validity window for a newly created certificate.</param>
    /// <param name="renewBefore">
    /// How long before expiry a replacement is created. Must be shorter than
    /// <paramref name="lifetime"/>; it doubles as the overlap window during which both the old
    /// and the new certificate are registered.
    /// </param>
    /// <param name="now">Current time, injectable so rotation is testable without waiting years.</param>
    public static IReadOnlyList<X509Certificate2> EnsureCertificates(
        string keysDirectory,
        string role,
        string subject,
        TimeSpan lifetime,
        TimeSpan renewBefore,
        DateTimeOffset now,
        ISecretProtector protector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(keysDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(role);
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);

        if (lifetime <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(lifetime), lifetime, "Certificate lifetime must be positive.");

        if (renewBefore <= TimeSpan.Zero || renewBefore >= lifetime)
        {
            throw new ArgumentOutOfRangeException(nameof(renewBefore), renewBefore,
                "Renewal lead time must be positive and shorter than the certificate lifetime, " +
                "otherwise a freshly created certificate is already due for replacement.");
        }

        Directory.CreateDirectory(keysDirectory);

        var certificates = LoadUsable(keysDirectory, role, now, protector);

        // Rotate when nothing on disk outlives the renewal window. An empty directory takes the
        // same path, so first run and rotation are one code path rather than two.
        var newest = certificates.Count > 0 ? certificates[0].NotAfter : DateTime.MinValue;
        if (newest.ToUniversalTime() <= (now + renewBefore).UtcDateTime)
        {
            certificates.Insert(0, Create(keysDirectory, role, subject, lifetime, now, protector));
        }

        return certificates;
    }

    /// <summary>
    /// Loads every non-expired certificate for the role, newest expiry first. Expired files are
    /// left on disk — they are inert once unregistered, and deleting key material as a side
    /// effect of a health-restoring startup path is not worth the risk of getting it wrong.
    /// </summary>
    private static List<X509Certificate2> LoadUsable(string keysDirectory, string role, DateTimeOffset now, ISecretProtector protector)
    {
        var certificates = new List<X509Certificate2>();

        foreach (var path in Directory.EnumerateFiles(keysDirectory, $"{role}*.pfx"))
        {
            X509Certificate2 certificate;
            try
            {
                var rawBytes = File.ReadAllBytes(path);
                byte[] pkcs12Bytes;
                try
                {
                    pkcs12Bytes = protector.Unprotect(rawBytes);
                }
                catch (CryptographicException)
                {
                    // Not actually protected — a legacy file from before this change. Adopt it as
                    // plaintext PKCS12 rather than fail, same precedent as the CA key's
                    // legacy-plain-PEM handling.
                    pkcs12Bytes = rawBytes;
                }

                certificate = X509CertificateLoader.LoadPkcs12(
                    pkcs12Bytes, password: null, keyStorageFlags: X509KeyStorageFlags.Exportable);
            }
            catch (CryptographicException)
            {
                // A file that cannot be read is not a reason to refuse to start: the rotation
                // below will mint a working certificate. Skipping beats throwing here, because
                // throwing would make one corrupt file a permanent outage.
                continue;
            }

            if (certificate.NotAfter.ToUniversalTime() <= now.UtcDateTime || !certificate.HasPrivateKey)
            {
                certificate.Dispose();
                continue;
            }

            certificates.Add(certificate);
        }

        certificates.Sort((left, right) => right.NotAfter.CompareTo(left.NotAfter));
        return certificates;
    }

    private static X509Certificate2 Create(
        string keysDirectory, string role, string subject, TimeSpan lifetime, DateTimeOffset now, ISecretProtector protector)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Backdated by a day so a small clock skew between this host and a relying party cannot
        // make a certificate that was just created look not-yet-valid.
        using var created = request.CreateSelfSigned(now.AddDays(-1), now + lifetime);

        // Timestamped name: rotation adds a file rather than replacing one, so the retiring
        // certificate stays loadable for the whole overlap window.
        var path = Path.Combine(keysDirectory, $"{role}-{now.UtcDateTime:yyyyMMddTHHmmssZ}.pfx");
        var pkcs12Bytes = created.Export(X509ContentType.Pfx);
        File.WriteAllBytes(path, protector.Protect(pkcs12Bytes));

        // Re-load through the same protect/unprotect + LoadPkcs12 path every subsequent start
        // uses, so any round-trip mismatch shows up now, not later.
        var reloadedBytes = protector.Unprotect(File.ReadAllBytes(path));
        return X509CertificateLoader.LoadPkcs12(
            reloadedBytes, password: null, keyStorageFlags: X509KeyStorageFlags.Exportable);
    }
}
