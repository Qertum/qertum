using System.Text.Json;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Cli.Root;

internal sealed record OfflineRootState(long CrlNumber, List<OfflineRootIssued> Issued, List<OfflineRootRevoked> Revoked);
internal sealed record OfflineRootIssued(string SerialHex, string SubjectDn, DateTime NotAfterUtc, string FileName);
internal sealed record OfflineRootRevoked(string SerialHex, DateTime RevokedAtUtc, string? Reason);
internal sealed record SignPreview(string SubjectDn, string Algorithm, int ValidityDays, DateTime NotAfterUtc, string Constraints, string CertificateFile);

/// <summary>
/// An offline root CA in a directory: <c>root.key</c> (PKCS#8, PBES2-encrypted with the operator's
/// passphrase), <c>root.pem</c>, <c>state.json</c> (CRL number, what it signed, what it revoked).
/// No network, no server. Signs through the same <see cref="CaCertificateBuilder"/> as the server.
/// </summary>
internal sealed class OfflineRoot(string directory, TimeProvider clock)
{
    public const string KeyFile = "root.key";
    public const string CertificateFile = "root.pem";
    public const string StateFile = "state.json";
    public const string CrlFile = "root.crl";
    public const string ChainFile = "chain.pem";

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    public void Init(X509Name subject, CertificateKeyAlgorithm algorithm, int validityDays, string passphrase)
    {
        if (Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any())
            throw new InvalidOperationException($"'{directory}' is not empty; refusing to overwrite an existing root.");
        // Owner-only, like every other key file qca writes: the key is passphrase-encrypted, but a copy invites unlimited
        // offline guessing.
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(directory);
        else Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var keyPair = AlgorithmStrategyFactory.CreateIssuer(algorithm).GenerateCaKeyPair(new SecureRandom());
        var now = clock.GetUtcNow().UtcDateTime;
        var certificate = CaCertificateBuilder.BuildRoot(new LocalKeyPairCaSigner(keyPair), subject, now.AddMinutes(-5), now.AddDays(validityDays));

        SecretFile.Write(Path.Combine(directory, KeyFile),
            System.Text.Encoding.UTF8.GetBytes(QertumKeyCodec.WriteEncryptedPrivateKeyPem(keyPair.Private, passphrase)), overwrite: false);
        File.WriteAllText(Path.Combine(directory, CertificateFile), QertumKeyCodec.WriteCertificatePem(certificate));
        WriteState(new OfflineRootState(0, [], []));
    }

    public SignPreview Preview(IntermediateRequestFile request)
    {
        var (csr, algorithm) = ReadRequest(request);
        var notAfter = clock.GetUtcNow().UtcDateTime.AddDays(request.ValidityDays);
        return new SignPreview(csr.GetCertificationRequestInfo().Subject.ToString(), algorithm.ToCanonicalString(),
            request.ValidityDays, notAfter, IssuerCeremonyText.Describe(Profile(request)), CertificateFileName(request));
    }

    public (string CertificatePath, string ChainPath) Sign(IntermediateRequestFile request, string passphrase)
    {
        if (request.Format != IntermediateRequestFile.CurrentFormat)
            throw new InvalidOperationException($"Unsupported request file format '{request.Format}'.");
        var (csr, _) = ReadRequest(request);
        var fileName = CertificateFileName(request);
        var certificatePath = Path.Combine(directory, fileName);
        if (File.Exists(certificatePath))
            throw new InvalidOperationException($"'{certificatePath}' already exists; refusing to overwrite it. Rename the request or move the file.");
        var rootCertificate = ReadCertificate();
        var signer = new LocalKeyPairCaSigner(LoadKeyPair(passphrase, rootCertificate));
        var now = clock.GetUtcNow().UtcDateTime;
        var notAfter = now.AddDays(request.ValidityDays);
        if (notAfter > rootCertificate.NotAfter.ToUniversalTime())
            throw new InvalidOperationException(
                $"The requested validity ends {notAfter:yyyy-MM-dd}, after this root expires ({rootCertificate.NotAfter:yyyy-MM-dd}).");

        var state = ReadState();
        var info = csr.GetCertificationRequestInfo();
        var certificate = CaCertificateBuilder.IssueSubordinate(signer, rootCertificate, info.SubjectPublicKeyInfo, info.Subject,
            Profile(request), now.AddMinutes(-5), notAfter);

        var chainPath = Path.Combine(directory, ChainFile);
        using (var output = new FileStream(certificatePath, FileMode.CreateNew, FileAccess.Write))
        using (var writer = new StreamWriter(output))
            writer.Write(QertumKeyCodec.WriteCertificatePem(certificate));
        File.WriteAllText(chainPath, QertumKeyCodec.WriteCertificatePem(rootCertificate));

        state.Issued.Add(new OfflineRootIssued(certificate.SerialNumber.ToString(16).ToUpperInvariant(),
            info.Subject.ToString(), notAfter, fileName));
        WriteState(state);
        return (certificatePath, chainPath);
    }

    public string Crl(IReadOnlyList<(string SerialHex, string? Reason)> revoke, int validityDays, string passphrase)
    {
        var rootCertificate = ReadCertificate();
        var signer = new LocalKeyPairCaSigner(LoadKeyPair(passphrase, rootCertificate));
        var now = clock.GetUtcNow().UtcDateTime;
        var state = ReadState();
        foreach (var (serial, reason) in revoke)
        {
            var normalized = serial.TrimStart('0').ToUpperInvariant();
            if (state.Revoked.All(r => r.SerialHex != normalized))
                state.Revoked.Add(new OfflineRootRevoked(normalized, now, reason));
        }

        var number = state.CrlNumber + 1;
        var der = CaCertificateBuilder.BuildCrl(signer, rootCertificate,
            state.Revoked.Select(r => new OfflineRevocation(r.SerialHex, r.RevokedAtUtc, r.Reason)),
            number, now, now.AddDays(validityDays));
        var path = Path.Combine(directory, CrlFile);
        File.WriteAllBytes(path, der);
        WriteState(state with { CrlNumber = number });
        return path;
    }

    private static (Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest Csr, CertificateKeyAlgorithm Algorithm) ReadRequest(IntermediateRequestFile request)
    {
        var csr = QertumKeyCodec.ReadCertificationRequestPem(request.CsrPem);
        if (!QertumKeyCodec.VerifySelfSignature(csr))
            throw new InvalidOperationException("The request's CSR signature does not verify; the file was altered or damaged.");
        var algorithm = CertificateGenerator.DetectAlgorithmFromCsr(Base64UrlText.Encode(csr.GetDerEncoded()));
        return (csr, algorithm);
    }

    private static SubordinateCaProfile Profile(IntermediateRequestFile r) =>
        new(r.PathLength, r.PermittedDnsSuffixes, r.ExcludedDnsSuffixes, r.PermittedIpRanges, r.ExcludedIpRanges);

    private AsymmetricCipherKeyPair LoadKeyPair(string passphrase, X509Certificate rootCertificate)
    {
        var privateKey = QertumKeyCodec.ReadEncryptedPrivateKeyPem(File.ReadAllText(Path.Combine(directory, KeyFile)), passphrase);
        return new AsymmetricCipherKeyPair(QertumKeyCodec.PublicKeyOf(rootCertificate), privateKey);
    }

    private X509Certificate ReadCertificate() =>
        QertumKeyCodec.ReadCertificatePem(File.ReadAllText(Path.Combine(directory, CertificateFile)))
        ?? throw new InvalidOperationException($"{CertificateFile} holds no certificate.");

    private OfflineRootState ReadState() =>
        JsonSerializer.Deserialize<OfflineRootState>(File.ReadAllText(Path.Combine(directory, StateFile)))
        ?? throw new InvalidOperationException($"{StateFile} is empty.");

    private void WriteState(OfflineRootState state) =>
        File.WriteAllText(Path.Combine(directory, StateFile), JsonSerializer.Serialize(state, Json));

    /// <summary>
    /// The signed certificate's file, from the request's (unauthenticated) name. A name that would land on the root's own
    /// files (root.pem, chain.pem; compared ignoring case for case-insensitive file systems) is refused, and Sign never
    /// overwrites, so a crafted request cannot replace the root certificate.
    /// </summary>
    internal static string CertificateFileName(IntermediateRequestFile request)
    {
        var stem = string.Concat(request.Name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '-')).Trim('-') is { Length: > 0 } safe
            ? safe : "intermediate";
        var fileName = stem + ".pem";
        if (fileName.Equals(CertificateFile, StringComparison.OrdinalIgnoreCase) || fileName.Equals(ChainFile, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"The request is named '{request.Name}', which would overwrite {fileName} in the root directory; refusing to sign it.");
        return fileName;
    }
}
