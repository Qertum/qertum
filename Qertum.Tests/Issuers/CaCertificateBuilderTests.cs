using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;
using Qertum.Tests.Crypto;

namespace Qertum.Tests.Issuers;

public sealed class CaCertificateBuilderTests
{
    private static readonly DateTime Now = new(2026, 9, 27, 12, 0, 0, DateTimeKind.Utc);

    internal static (AsymmetricCipherKeyPair Key, X509Certificate Cert) Root(CertificateKeyAlgorithm algorithm = CertificateKeyAlgorithm.Rsa, string cn = "Offline Root")
    {
        var key = AlgorithmStrategyFactory.CreateIssuer(algorithm).GenerateCaKeyPair(new SecureRandom());
        var cert = CaCertificateBuilder.BuildRoot(new LocalKeyPairCaSigner(key),
            CaCertificateBuilder.SubjectName(cn, "Qertum", null, "FI", null, null), Now.AddMinutes(-5), Now.AddYears(20));
        return (key, cert);
    }

    private static readonly SubordinateCaProfile Constrained = new(0, ["corp.example"], ["secret.corp.example"], ["10.0.0.0/8"], ["10.9.0.0/16"]);

    [Theory]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65)]
    public void Subordinate_CarriesTheProfile_AndVerifiesUnderTheRoot(CertificateKeyAlgorithm algorithm)
    {
        var (rootKey, rootCert) = Root(algorithm);
        var subKey = AlgorithmStrategyFactory.CreateIssuer(algorithm).GenerateCaKeyPair(new SecureRandom());

        var sub = CaCertificateBuilder.IssueSubordinate(new LocalKeyPairCaSigner(rootKey), rootCert,
            QertumKeyCodec.ToSubjectPublicKeyInfo(subKey.Public), CaCertificateBuilder.SubjectName("Issuing CA", null, null, null, null, null),
            Constrained, Now, Now.AddYears(5));

        Assert.True(sub.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(rootCert))));
        var facts = IssuerCertificateFacts.Read(sub);
        Assert.True(facts.IsCa);
        Assert.False(facts.IsSelfSigned);
        Assert.True(facts.HasKeyCertSign);
        Assert.Equal(0, facts.PathLengthConstraint);
        Assert.Equal(["corp.example"], facts.PermittedDnsSuffixes);
        Assert.Equal(["secret.corp.example"], facts.ExcludedDnsSuffixes);
        Assert.Equal(["10.0.0.0/8"], facts.PermittedIpRanges);
        Assert.Equal(["10.9.0.0/16"], facts.ExcludedIpRanges);
        Assert.True(sub.GetCriticalExtensionOids().Contains(X509Extensions.NameConstraints.Id));
    }

    [Fact]
    public void Unconstrained_HasNoNameConstraintsOrPathLength()
    {
        var (rootKey, rootCert) = Root();
        var subKey = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.Rsa).GenerateCaKeyPair(new SecureRandom());

        var sub = CaCertificateBuilder.IssueSubordinate(new LocalKeyPairCaSigner(rootKey), rootCert,
            QertumKeyCodec.ToSubjectPublicKeyInfo(subKey.Public), CaCertificateBuilder.SubjectName("Open CA", null, null, null, null, null),
            SubordinateCaProfile.Unconstrained, Now, Now.AddYears(5));

        Assert.Null(sub.GetExtensionValue(X509Extensions.NameConstraints));
        Assert.Null(IssuerCertificateFacts.Read(sub).PathLengthConstraint);
    }

    [Fact]
    public void Request_CarriesTheProfileAsAnExtensionRequest()
    {
        var key = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256).GenerateCaKeyPair(new SecureRandom());

        var csr = CaCertificateBuilder.BuildRequest(key, CaCertificateBuilder.SubjectName("Pending CA", null, null, null, null, null), Constrained);

        Assert.True(QertumKeyCodec.VerifySelfSignature(csr));
        var attribute = csr.GetCertificationRequestInfo().Attributes
            .Select(a => AttributePkcs.GetInstance(a))
            .Single(a => a.AttrType.Equals(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest));
        var extensions = X509Extensions.GetInstance(attribute.AttrValues[0]);
        Assert.NotNull(extensions.GetExtension(X509Extensions.BasicConstraints));
        Assert.NotNull(extensions.GetExtension(X509Extensions.NameConstraints));
        Assert.NotNull(extensions.GetExtension(X509Extensions.KeyUsage));
        var pem = QertumKeyCodec.WriteCertificationRequestPem(csr);
        Assert.Equal(csr.GetDerEncoded(), QertumKeyCodec.ReadCertificationRequestPem(pem).GetDerEncoded());
    }

    [Fact]
    public void Crl_ListsTheRevocations_AndVerifies()
    {
        var (rootKey, rootCert) = Root();

        var der = CaCertificateBuilder.BuildCrl(new LocalKeyPairCaSigner(rootKey), rootCert,
            [new OfflineRevocation("0A1B", Now.AddDays(-1), "keyCompromise")], 7, Now, Now.AddDays(365));

        var crl = new X509CrlParser().ReadCrl(der);
        Assert.True(crl.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(rootCert))));
        Assert.NotNull(crl.GetRevokedCertificate(new BigInteger("0A1B", 16)));
        Assert.Equal(7, DerInteger.GetInstance(Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(
            crl.GetExtensionValue(X509Extensions.CrlNumber))).LongValueExact);
    }

    [Fact]
    public void OpenSsl_RefusesALeafOutsideTheNameConstraints_AndAcceptsOneInside()
    {
        var openSsl = OpenSslTool.Find();
        if (openSsl is null) Assert.Skip("OpenSSL 3 is not installed.");
        var (rootKey, rootCert) = Root(CertificateKeyAlgorithm.EcdsaP256);
        var subKey = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256).GenerateCaKeyPair(new SecureRandom());
        var sub = CaCertificateBuilder.IssueSubordinate(new LocalKeyPairCaSigner(rootKey), rootCert,
            QertumKeyCodec.ToSubjectPublicKeyInfo(subKey.Public), CaCertificateBuilder.SubjectName("Constrained CA", null, null, null, null, null),
            new SubordinateCaProfile(0, ["corp.example"], [], [], []), Now.AddMinutes(-5), Now.AddYears(5));
        var dir = Directory.CreateTempSubdirectory("nc-").FullName;
        try
        {
            string Write(string name, string pem) { var p = Path.Combine(dir, name); File.WriteAllText(p, pem); return p; }
            var rootPath = Write("root.pem", QertumKeyCodec.WriteCertificatePem(rootCert));
            var subPath = Write("sub.pem", QertumKeyCodec.WriteCertificatePem(sub));
            string Leaf(string dns)
            {
                // Built by bypassing policy on purpose: this pins the extension's encoding, not our checks.
                var leafKey = AlgorithmStrategyFactory.Create(CertificateKeyAlgorithm.EcdsaP256).GenerateLeafKeyPair(new SecureRandom());
                var gen = new X509V3CertificateGenerator();
                gen.SetSerialNumber(BigInteger.ValueOf(Random.Shared.NextInt64(1, long.MaxValue)));
                gen.SetIssuerDN(sub.SubjectDN);
                gen.SetSubjectDN(new X509Name($"CN={dns}"));
                gen.SetNotBefore(Now.AddMinutes(-5));
                gen.SetNotAfter(Now.AddDays(30));
                gen.SetSubjectPublicKeyInfo(QertumKeyCodec.ToSubjectPublicKeyInfo(leafKey.Public));
                gen.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.DnsName, dns)));
                return Write($"{dns}.pem", QertumKeyCodec.WriteCertificatePem(gen.Generate(new LocalKeyPairCaSigner(subKey).CreateSignatureFactory())));
            }

            var inside = OpenSslTool.Run(openSsl!, $"verify -attime {new DateTimeOffset(Now).ToUnixTimeSeconds()} -CAfile {rootPath} -untrusted {subPath} {Leaf("www.corp.example")}");
            var outside = OpenSslTool.Run(openSsl!, $"verify -attime {new DateTimeOffset(Now).ToUnixTimeSeconds()} -CAfile {rootPath} -untrusted {subPath} {Leaf("www.evil.example")}");

            Assert.True(inside.ExitCode == 0, inside.Output);
            Assert.NotEqual(0, outside.ExitCode);
            Assert.Contains("subtree violation", outside.Output, StringComparison.OrdinalIgnoreCase);
        }
        finally { Directory.Delete(dir, true); }
    }
}
