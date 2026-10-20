using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Qertum.Services.Crypto;

namespace Qertum.Services.Issuers;

/// <summary>What Qertum needs to know about a CA certificate, parsed once.</summary>
public sealed record IssuerCertificateFacts(
    string SubjectDn,
    string SerialNumber,
    string SpkiSha256,
    string? SubjectKeyIdentifier,
    DateTime ValidFrom,
    DateTime ValidTo,
    bool IsCa,
    bool IsSelfSigned,
    int? PathLengthConstraint,
    IReadOnlyList<string> PermittedDnsSuffixes,
    IReadOnlyList<string> ExcludedDnsSuffixes,
    IReadOnlyList<string> PermittedIpRanges,
    IReadOnlyList<string> ExcludedIpRanges,
    bool HasKeyCertSign,
    CertificateKeyAlgorithm? KeyAlgorithm)
{
    public static IssuerCertificateFacts Read(string pem) =>
        Read(QertumKeyCodec.ReadCertificatePem(pem) ?? throw new ArgumentException("The PEM holds no certificate.", nameof(pem)));

    public static IssuerCertificateFacts Read(X509Certificate certificate)
    {
        var bc = ReadBasicConstraints(certificate);
        var (permittedDns, excludedDns, permittedIp, excludedIp) = ReadNameConstraints(certificate);
        var keyUsage = certificate.GetKeyUsage();
        CertificateKeyAlgorithm? algorithm;
        try { algorithm = CertificateGenerator.DetectAlgorithmFromCertificatePem(QertumKeyCodec.WriteCertificatePem(certificate)); }
        catch (NotSupportedException) { algorithm = null; }

        return new IssuerCertificateFacts(
            certificate.SubjectDN.ToString(),
            certificate.SerialNumber.ToString(16).ToUpperInvariant(),
            SpkiSha256Of(certificate),
            ReadSubjectKeyIdentifier(certificate),
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime(),
            bc?.IsCA() == true,
            certificate.SubjectDN.Equivalent(certificate.IssuerDN) && VerifiesWithOwnKey(certificate),
            bc?.IsCA() == true ? bc.PathLenConstraint?.IntValueExact : null,
            permittedDns, excludedDns, permittedIp, excludedIp,
            // KeyUsage absent = unrestricted (RFC 5280 §4.2.1.3).
            keyUsage is null || keyUsage[5],
            algorithm);
    }

    public static string SpkiSha256Of(X509Certificate certificate) =>
        Convert.ToHexStringLower(SHA256.HashData(certificate.CertificateStructure.SubjectPublicKeyInfo.GetDerEncoded()));

    public void ApplyTo(Issuer issuer)
    {
        issuer.SubjectDn = SubjectDn;
        issuer.SerialNumber = SerialNumber;
        issuer.SpkiSha256 = SpkiSha256;
        issuer.SubjectKeyIdentifier = SubjectKeyIdentifier;
        issuer.ValidFrom = ValidFrom;
        issuer.ValidTo = ValidTo;
        issuer.PathLengthConstraint = PathLengthConstraint;
        issuer.PermittedDnsSuffixesJson = JsonSerializer.Serialize(PermittedDnsSuffixes);
        issuer.ExcludedDnsSuffixesJson = JsonSerializer.Serialize(ExcludedDnsSuffixes);
        issuer.PermittedIpRangesJson = JsonSerializer.Serialize(PermittedIpRanges);
        issuer.ExcludedIpRangesJson = JsonSerializer.Serialize(ExcludedIpRanges);
        issuer.KeyAlgorithm = KeyAlgorithm;
    }

    private static BasicConstraints? ReadBasicConstraints(X509Certificate certificate)
    {
        var value = certificate.GetExtensionValue(X509Extensions.BasicConstraints);
        return value is null ? null : BasicConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(value));
    }

    private static string? ReadSubjectKeyIdentifier(X509Certificate certificate)
    {
        var value = certificate.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
        return value is null
            ? null
            : Convert.ToHexStringLower(Org.BouncyCastle.Asn1.X509.SubjectKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(value)).GetKeyIdentifier());
    }

    private static bool VerifiesWithOwnKey(X509Certificate certificate)
    {
        try
        {
            return certificate.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(certificate)));
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static (List<string>, List<string>, List<string>, List<string>) ReadNameConstraints(X509Certificate certificate)
    {
        List<string> permittedDns = [], excludedDns = [], permittedIp = [], excludedIp = [];
        var value = certificate.GetExtensionValue(X509Extensions.NameConstraints);
        if (value is null) return (permittedDns, excludedDns, permittedIp, excludedIp);

        var constraints = NameConstraints.GetInstance(X509ExtensionUtilities.FromExtensionValue(value));
        Collect(constraints.PermittedSubtreesValue?.ToAsn1Object() as Asn1Sequence, permittedDns, permittedIp);
        Collect(constraints.ExcludedSubtreesValue?.ToAsn1Object() as Asn1Sequence, excludedDns, excludedIp);
        return (permittedDns, excludedDns, permittedIp, excludedIp);
    }

    private static void Collect(Asn1Sequence? subtrees, List<string> dns, List<string> ip)
    {
        if (subtrees is null) return;
        foreach (var entry in subtrees)
        {
            var name = GeneralSubtree.GetInstance(entry).Base;
            switch (name.TagNo)
            {
                case GeneralName.DnsName:
                    dns.Add(DerIA5String.GetInstance(name.Name).GetString().TrimStart('.').ToLowerInvariant());
                    break;
                case GeneralName.IPAddress:
                    ip.Add(ToCidr(Asn1OctetString.GetInstance(name.Name).GetOctets()));
                    break;
            }
        }
    }

    /// <summary>RFC 5280 §4.2.1.10: address octets followed by mask octets (8 for IPv4, 32 for IPv6).</summary>
    internal static string ToCidr(byte[] octets)
    {
        var half = octets.Length / 2;
        var address = new IPAddress(octets[..half]);
        var prefix = octets[half..].Sum(b => System.Numerics.BitOperations.PopCount(b));
        return $"{address}/{prefix}";
    }
}
