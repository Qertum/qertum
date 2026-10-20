namespace Qertum.Services.Issuers;

/// <summary>
/// Where an online issuer's key and certificate live. The legacy issuer keeps the pre-hierarchy
/// files <c>CaData/ca.key</c> + <c>ca.pem</c>; every other issuer gets <c>CaData/issuers/{id}/</c>
/// holding files of the same names, so <see cref="CertificateGenerator"/> works unchanged on either.
/// </summary>
public sealed class IssuerStorage(CaDataOptions caData)
{
    public string DirectoryFor(Issuer issuer) =>
        issuer.LegacyFiles
            ? caData.Directory
            : Path.Combine(caData.Directory, "issuers", issuer.Id.Value.ToString("N"));

    public CaDataOptions OptionsFor(Issuer issuer) => new() { Directory = DirectoryFor(issuer) };

    public string KeyPath(Issuer issuer) => Path.Combine(DirectoryFor(issuer), "ca.key");

    public string CertificatePath(Issuer issuer) => Path.Combine(DirectoryFor(issuer), "ca.pem");

    public bool HasKeyFile(Issuer issuer) => File.Exists(KeyPath(issuer));

    /// <summary>Deletes the issuer's key and certificate files. Missing files are not an error.</summary>
    public void DeleteFiles(Issuer issuer)
    {
        var dir = DirectoryFor(issuer);
        // File.Delete tolerates a missing file but not a missing directory.
        if (!Directory.Exists(dir)) return;
        File.Delete(KeyPath(issuer));
        File.Delete(CertificatePath(issuer));
        if (!issuer.LegacyFiles && !Directory.EnumerateFileSystemEntries(dir).Any())
            Directory.Delete(dir);
    }
}
