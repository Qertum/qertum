using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Qertum.Services;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace Qertum.Cli.Doctor;

/// <summary>Whether a root certificate is present in this machine's trusted-root stores.</summary>
internal enum RootStoreAnswer { Installed, NotInstalled, CannotTell }

/// <summary>Read-only lookup of a root by its SHA-256 fingerprint (hex).</summary>
internal interface IRootStore
{
    RootStoreAnswer Lookup(string sha256Hex);
}

/// <summary>
/// The current user's, then the machine's, trusted-root store. Never writes. Presence in the store is
/// all it reports, not that the certificate is trusted for TLS, and not browser, JVM or Firefox stores.
/// </summary>
internal sealed class OsRootStore : IRootStore
{
    public RootStoreAnswer Lookup(string sha256Hex)
    {
        var readAny = false;
        foreach (var location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            try
            {
                using var store = new X509Store(StoreName.Root, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                readAny = true;
                foreach (var certificate in store.Certificates)
                {
                    using (certificate)
                    {
                        if (Convert.ToHexString(SHA256.HashData(certificate.RawData)).Equals(sha256Hex, StringComparison.OrdinalIgnoreCase))
                            return RootStoreAnswer.Installed;
                    }
                }
            }
            catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException or IOException or UnauthorizedAccessException)
            {
                // This store cannot be read on this platform; the other may still answer.
            }
        }

        return readAny ? RootStoreAnswer.NotInstalled : RootStoreAnswer.CannotTell;
    }
}

/// <summary>What earlier checks learned, for later ones to reuse instead of fetching again.</summary>
internal sealed class DoctorShared
{
    public bool ApiReachable { get; set; }

    public bool SessionAccepted { get; set; }

    public MyAccessResponse? Access { get; set; }

    public IReadOnlyList<IssuerResponse>? Issuers { get; set; }

    public IReadOnlyList<BcCertificate> Roots { get; set; } = [];

    public IReadOnlyList<BcCertificate> IssuerCertificates { get; set; } = [];
}

/// <summary>Everything a check needs: resolved inputs, the HTTP handler, the clock and the shared results.</summary>
internal sealed class DoctorContext
{
    /// <summary>The API base URL, trimmed, no trailing slash; null when none is known.</summary>
    public string? ApiUrl { get; init; }

    public string? IdentityUrl { get; init; }

    /// <summary>The bearer token, or null when there is none or it is already expired locally.</summary>
    public string? Token { get; init; }

    /// <summary>Why there is no usable token ("not logged in", "the token expired at …").</summary>
    public string? TokenProblem { get; init; }

    public required HttpMessageHandler Handler { get; init; }

    public required TimeProvider Clock { get; init; }

    public required IRootStore RootStore { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    public DoctorShared Shared { get; } = new();

    public DateTime NowUtc => Clock.GetUtcNow().UtcDateTime;
}
