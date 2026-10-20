using System.Net;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services.Crypto;

namespace Qertum.Services.Issuers;

/// <summary>
/// Builds CA certificates, CA certificate requests and offline CRLs. Shared by the server
/// (<see cref="CertificateGenerator"/>) and the offline <c>qca root</c> commands so both produce
/// the same extensions. Signs only through <see cref="ICaSigner"/>.
/// </summary>
public static class CaCertificateBuilder
{
    public static X509Name SubjectName(string commonName, string? organization, string? organizationalUnit,
        string? country, string? state, string? locality)
    {
        var attrs = new List<string> { $"CN={commonName}" };
        if (!string.IsNullOrWhiteSpace(organization)) attrs.Add($"O={organization}");
        if (!string.IsNullOrWhiteSpace(organizationalUnit)) attrs.Add($"OU={organizationalUnit}");
        if (!string.IsNullOrWhiteSpace(country)) attrs.Add($"C={country}");
        if (!string.IsNullOrWhiteSpace(state)) attrs.Add($"ST={state}");
        if (!string.IsNullOrWhiteSpace(locality)) attrs.Add($"L={locality}");
        return new X509Name(string.Join(", ", attrs));
    }

    public static X509Certificate BuildRoot(ICaSigner signer, X509Name subject, DateTime notBefore, DateTime notAfter)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(CertificateGenerator.GenerateSerialNumber(new SecureRandom()));
        generator.SetIssuerDN(subject);
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetSubjectDN(subject);
        generator.SetSubjectPublicKeyInfo(QertumKeyCodec.ToSubjectPublicKeyInfo(signer.PublicKey));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        generator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));
        // RFC 5280 §4.2.1.2: what every issued certificate's AKI points back to. No AKI on a root.
        generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, QertumKeyCodec.SubjectKeyIdentifierFor(signer.PublicKey));
        return generator.Generate(signer.CreateSignatureFactory());
    }

    public static X509Certificate IssueSubordinate(ICaSigner issuerSigner, X509Certificate issuerCertificate,
        SubjectPublicKeyInfo subjectKey, X509Name subject, SubordinateCaProfile profile,
        DateTime notBefore, DateTime notAfter, IssuerUrls? urls = null)
    {
        var subjectPublicKey = QertumKeyCodec.PublicKeyOf(subjectKey);
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(CertificateGenerator.GenerateSerialNumber(new SecureRandom()));
        generator.SetIssuerDN(issuerCertificate.SubjectDN);
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetSubjectDN(subject);
        generator.SetSubjectPublicKeyInfo(subjectKey);
        foreach (var oid in CaExtensions(profile).ExtensionOids)
        {
            var extension = CaExtensions(profile).GetExtension(oid);
            generator.AddExtension(oid, extension.IsCritical, extension.GetParsedValue());
        }
        generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, QertumKeyCodec.SubjectKeyIdentifierFor(subjectPublicKey));
        generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, QertumKeyCodec.AuthorityKeyIdentifierFor(issuerCertificate));
        if (!string.IsNullOrWhiteSpace(urls?.CrlDistributionPoint))
            generator.AddExtension(X509Extensions.CrlDistributionPoints, false, new CrlDistPoint([
                new DistributionPoint(new DistributionPointName(new GeneralNames(
                    new GeneralName(GeneralName.UniformResourceIdentifier, urls.CrlDistributionPoint))), null, null)]));
        return generator.Generate(issuerSigner.CreateSignatureFactory());
    }

    /// <summary>BasicConstraints (critical, cA, pathLen), KeyUsage (critical, keyCertSign | cRLSign) and, when any, NameConstraints (critical, RFC 5280 §4.2.1.10).</summary>
    public static X509Extensions CaExtensions(SubordinateCaProfile profile)
    {
        var extensions = new Dictionary<DerObjectIdentifier, X509Extension>
        {
            [X509Extensions.BasicConstraints] = new(true, new DerOctetString(
                (profile.PathLength is int pathLength ? new BasicConstraints(pathLength) : new BasicConstraints(true)).GetEncoded())),
            [X509Extensions.KeyUsage] = new(true, new DerOctetString(new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign).GetEncoded()))
        };
        if (profile.HasNameConstraints)
        {
            var constraints = new NameConstraints(
                AsGeneralSubtrees(Subtrees(profile.PermittedDnsSuffixes, profile.PermittedIpRanges)),
                AsGeneralSubtrees(Subtrees(profile.ExcludedDnsSuffixes, profile.ExcludedIpRanges)));
            extensions[X509Extensions.NameConstraints] = new(true, new DerOctetString(constraints.GetEncoded()));
        }
        return new X509Extensions(extensions);
    }

    public static Pkcs10CertificationRequest BuildRequest(AsymmetricCipherKeyPair keyPair, X509Name subject, SubordinateCaProfile profile)
    {
        // PKCS#9 extensionRequest: `openssl ca -copy_extensions copy` (or x509 -copy_extensions) reproduces them.
        var attributes = new DerSet(new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(CaExtensions(profile))));
        return new Pkcs10CertificationRequest(
            QertumKeyCodec.SignatureFactoryFor(keyPair.Private), subject,
            QertumKeyCodec.ToSubjectPublicKeyInfo(keyPair.Public), attributes);
    }

    public static byte[] BuildCrl(ICaSigner signer, X509Certificate issuerCertificate, IEnumerable<OfflineRevocation> revoked,
        long crlNumber, DateTime thisUpdateUtc, DateTime nextUpdateUtc)
    {
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(issuerCertificate.SubjectDN);
        generator.SetThisUpdate(thisUpdateUtc);
        generator.SetNextUpdate(nextUpdateUtc);
        generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, QertumKeyCodec.AuthorityKeyIdentifierFor(issuerCertificate));
        generator.AddExtension(X509Extensions.CrlNumber, false, new CrlNumber(BigInteger.ValueOf(crlNumber)));
        foreach (var entry in revoked)
            generator.AddCrlEntry(new BigInteger(entry.SerialHex, 16), entry.RevokedAtUtc, CertificateGenerator.MapRevocationReason(entry.Reason));
        return generator.Generate(signer.CreateSignatureFactory()).GetEncoded();
    }

    private static GeneralSubtrees? AsGeneralSubtrees(IReadOnlyCollection<GeneralSubtree>? subtrees) =>
        subtrees is null ? null : GeneralSubtrees.GetInstance(new DerSequence(subtrees.ToArray<Asn1Encodable>()));

    /// <summary>The subtrees for one side, or null when empty: RFC 5280 forbids an empty SEQUENCE of subtrees.</summary>
    private static IReadOnlyCollection<GeneralSubtree>? Subtrees(IReadOnlyList<string> dnsSuffixes, IReadOnlyList<string> ipRanges)
    {
        var subtrees = dnsSuffixes.Select(d => new GeneralSubtree(new GeneralName(GeneralName.DnsName, d))).ToList();
        foreach (var range in ipRanges)
        {
            var network = IPNetwork.Parse(range);
            var address = network.BaseAddress.GetAddressBytes();
            var mask = new byte[address.Length];
            for (var bit = 0; bit < network.PrefixLength; bit++) mask[bit / 8] |= (byte)(0x80 >> (bit % 8));
            subtrees.Add(new GeneralSubtree(new GeneralName(GeneralName.IPAddress, new DerOctetString([.. address, .. mask]))));
        }
        return subtrees.Count == 0 ? null : subtrees;
    }
}
