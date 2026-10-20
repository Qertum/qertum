using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;

namespace Qertum.Services.Issuers;

/// <summary>
/// Reads an online issuer's signing key back out of its key file, for the administrator-only export
/// (<c>GET /v1/issuers/{id}/private-key</c>, <c>POST …/pfx</c>). The key file is the only place the key lives.
/// </summary>
public sealed class IssuerKeyExporter(IssuerStorage storage, IDataProtectionProvider dataProtection)
{
    private readonly IDataProtector _keyProtector = dataProtection.CreateProtector("Qertum.CaPrivateKey");

    /// <summary>
    /// The issuer's private key PEM, or null when this host holds none: an offline issuer, one still awaiting
    /// its certificate, or an archived one whose key was deleted.
    /// </summary>
    /// <exception cref="InvalidOperationException">The key file cannot be decrypted (the Data Protection key ring changed).</exception>
    public string? ReadKeyPem(Issuer issuer)
    {
        if (issuer.KeyCustody != IssuerKeyCustody.Online
            || issuer.Status is not (IssuerStatus.Active or IssuerStatus.Retired)
            || !storage.HasKeyFile(issuer))
            return null;

        var stored = File.ReadAllText(storage.KeyPath(issuer));
        // Files written before encryption was introduced start with -----BEGIN.
        if (stored.StartsWith("-----BEGIN", StringComparison.Ordinal)) return stored;
        try
        {
            return _keyProtector.Unprotect(stored);
        }
        catch (CryptographicException)
        {
            throw new InvalidOperationException("CA private key could not be decrypted. The Data Protection key ring may have changed.");
        }
    }
}
