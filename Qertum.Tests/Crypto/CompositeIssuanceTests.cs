using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Crypto.Composite;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Crypto;

/// <summary>
/// A composite root is created, stored, reloaded and used the same way as every other root: it
/// issues composite and classical leaves, signs full and delta CRLs and OCSP responses, and each of
/// those verifies with the key read back out of its certificate.
/// </summary>
public sealed class CompositeIssuanceTests : IDisposable
{
    private readonly IDataProtectionProvider _dataProtection = new EphemeralDataProtectionProvider();
    private readonly List<string> _directories = [];

    public static TheoryData<string> Names => CompositeTestVectors.AlgorithmNames;

    public void Dispose()
    {
        foreach (var directory in _directories.Where(Directory.Exists))
            try { Directory.Delete(directory, recursive: true); } catch { /* best effort */ }
    }

    [Theory]
    [MemberData(nameof(Names))]
    public void CompositeRootSurvivesAReloadAndIssuesAVerifiableLeaf(string name)
    {
        var algorithm = CompositeAlgorithms.FindByName(name)!.ToKeyAlgorithm();
        var directory = NewDirectory();
        NewGenerator(directory).GenerateCa(new GenerateCaRequest { CommonName = "Composite Root", KeyAlgorithm = algorithm, ValidityDays = 365 });

        // A fresh generator reads ca.key and ca.pem back, as a restarted process does.
        var reloaded = NewGenerator(directory);
        var leaf = reloaded.GenerateCertificate(
            new CertificateRequest { CommonName = "leaf.composite.local", KeyAlgorithm = algorithm }, new CaSettings { PqcStage = PqcStage.Off });

        var root = QertumKeyCodec.ReadCertificatePem(reloaded.GetCaCertificatePem())!;
        var issued = QertumKeyCodec.ReadCertificatePem(leaf.CertificatePem)!;
        root.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(root)));
        issued.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(root)));
        Assert.IsType<CompositePublicKey>(QertumKeyCodec.PublicKeyOf(issued));
        Assert.IsType<CompositePrivateKey>(QertumKeyCodec.ReadPrivateKeyPem(leaf.PrivateKeyPem));
        Assert.Equal(name, reloaded.GetCaStatus().Algorithm);
        Assert.Equal(algorithm, CertificateGenerator.DetectAlgorithmFromCertificatePem(leaf.CertificatePem));
    }

    [Fact]
    public void CompositeLeafCarriesSignatureOnlyKeyUsageAndPointsAtItsIssuer()
    {
        var generator = NewRoot(CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512);

        var leaf = QertumKeyCodec.ReadCertificatePem(generator.GenerateCertificate(
            new CertificateRequest { CommonName = "usage.composite.local", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512 },
            new CaSettings { PqcStage = PqcStage.Off }).CertificatePem)!;
        var root = QertumKeyCodec.ReadCertificatePem(generator.GetCaCertificatePem())!;

        Assert.False(leaf.GetKeyUsage()?[2] ?? false, "keyEncipherment");
        Assert.False(leaf.GetKeyUsage()?[3] ?? false, "dataEncipherment");
        Assert.Equal(
            X509ExtensionUtilities.GetSubjectKeyIdentifier(root).GetKeyIdentifier(),
            X509ExtensionUtilities.GetAuthorityKeyIdentifier(leaf).KeyIdentifier.GetOctets());
    }

    [Fact]
    public void ClassicalRootIssuesACompositeLeafAndCompositeRootIssuesAClassicalLeaf()
    {
        var rsaRoot = NewRoot(CertificateKeyAlgorithm.Rsa);
        var compositeUnderRsa = QertumKeyCodec.ReadCertificatePem(rsaRoot.GenerateCertificate(
            new CertificateRequest { CommonName = "c.rsa.local", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa44EcdsaP256Sha256 },
            new CaSettings { PqcStage = PqcStage.Off }).CertificatePem)!;
        compositeUnderRsa.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(QertumKeyCodec.ReadCertificatePem(rsaRoot.GetCaCertificatePem())!)));
        Assert.IsType<CompositePublicKey>(QertumKeyCodec.PublicKeyOf(compositeUnderRsa));

        var compositeRoot = NewRoot(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512);
        var ecdsaUnderComposite = QertumKeyCodec.ReadCertificatePem(compositeRoot.GenerateCertificate(
            new CertificateRequest { CommonName = "e.composite.local", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256 },
            new CaSettings { PqcStage = PqcStage.Off }).CertificatePem)!;
        ecdsaUnderComposite.Verify(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(QertumKeyCodec.ReadCertificatePem(compositeRoot.GetCaCertificatePem())!)));
        Assert.Equal("MLDSA65-ECDSA-P256-SHA512", CompositeAlgorithms.FindByOid(new Org.BouncyCastle.Asn1.DerObjectIdentifier(ecdsaUnderComposite.SigAlgOid))!.Name);
    }

    [Fact]
    public void CompositeRootSignsFullAndDeltaCrls()
    {
        var generator = NewRoot(CertificateKeyAlgorithm.MlDsa87EcdsaP384Sha512);
        var leaf = generator.GenerateCertificate(new CertificateRequest { CommonName = "r.composite.local" }, new CaSettings { PqcStage = PqcStage.Off });
        var revoked = new CertificateRequest
        {
            CommonName = "r.composite.local",
            Status = CertificateRequestStatus.Revoked,
            CertificatePem = leaf.CertificatePem,
            RevokedAtUtc = DateTime.UtcNow.AddMinutes(-1),
            RevocationReason = "keyCompromise"
        };
        var rootKey = QertumKeyCodec.PublicKeyOf(QertumKeyCodec.ReadCertificatePem(generator.GetCaCertificatePem())!);

        var full = new X509CrlParser().ReadCrl(generator.GenerateCrl([revoked], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 1));
        var delta = new X509CrlParser().ReadCrl(generator.GenerateDeltaCrl([revoked], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2, baseCrlNumber: 1));

        foreach (var crl in new[] { full, delta })
        {
            crl.Verify(QertumKeyCodec.VerifierFor(rootKey));
            Assert.NotNull(crl.GetRevokedCertificate(QertumKeyCodec.ReadCertificatePem(leaf.CertificatePem)!.SerialNumber));
        }
    }

    [Fact]
    public void CompositeRootSignsOcspResponsesThatVerify()
    {
        var generator = NewRoot(CertificateKeyAlgorithm.MlDsa65Ed25519Sha512);
        var leaf = generator.GenerateCertificate(new CertificateRequest { CommonName = "o.composite.local" }, new CaSettings { PqcStage = PqcStage.Off });
        var root = QertumKeyCodec.ReadCertificatePem(generator.GetCaCertificatePem())!;
        var request = new OcspReqGenerator();
        request.AddRequest(new CertificateID(CertificateID.DigestSha1, root, new BigInteger(leaf.SerialNumber, 16)));

        var response = (BasicOcspResp)new OcspResp(generator.GenerateOcspResponse(
            request.Generate().GetEncoded(),
            new Dictionary<string, OcspCertificateStatus> { [leaf.SerialNumber] = OcspCertificateStatus.Good })).GetResponseObject();

        Assert.Null(Assert.Single(response.Responses).GetCertStatus()); // good: the CertID matched this issuer
        Assert.Equal(QertumKeyCodec.ResponderIdByKey(root), response.ResponderId);
        var verifier = QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(root))
            .CreateVerifierFactory(BasicOcspResponse.GetInstance(response.GetEncoded()).SignatureAlgorithm).CreateCalculator();
        var tbs = response.GetTbsResponseData();
        using (var stream = verifier.Stream)
            stream.Write(tbs, 0, tbs.Length);
        Assert.True(verifier.GetResult().IsVerified(response.GetSignature()));
    }

    [Fact]
    public void CompositeCsrIsDetectedAndIssuedAgainstItsOwnKey()
    {
        var generator = NewRoot(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512);
        var csr = TestCsrBuilder.BuildCompositeBase64Url("csr.composite.local", ["csr.composite.local"], "MLDSA87-ECDSA-P384-SHA512");

        var detected = CertificateGenerator.DetectAlgorithmFromCsr(csr);
        var issued = generator.GenerateFromCsr(csr,
            new CertificateRequest { CommonName = "csr.composite.local", KeyAlgorithm = detected }, new CaSettings { PqcStage = PqcStage.Off });

        Assert.Equal(CertificateKeyAlgorithm.MlDsa87EcdsaP384Sha512, detected);
        Assert.Equal(string.Empty, issued.PrivateKeyPem);
        var csrKey = new Pkcs10CertificationRequest(Qertum.Services.Acme.JwkConverter.Base64UrlDecode(csr))
            .GetCertificationRequestInfo().SubjectPublicKeyInfo.GetEncoded();
        Assert.Equal(csrKey, QertumKeyCodec.ReadCertificatePem(issued.CertificatePem)!.CertificateStructure.SubjectPublicKeyInfo.GetEncoded());
    }

    [Fact]
    public void ImportAcceptsAMatchingCompositeRootAndRefusesAMismatchedKey()
    {
        var algorithm = CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!;
        var keys = CompositeKeyPairGenerator.Generate(algorithm, new SecureRandom());
        var other = CompositeKeyPairGenerator.Generate(algorithm, new SecureRandom());
        var certificatePem = QertumKeyCodec.WriteCertificatePem(SelfSignedCa(keys, withSubjectKeyIdentifier: true));

        Assert.Throws<ArgumentException>(() => NewGenerator(NewDirectory()).ImportCa(new ImportCaRequest
        {
            CertificatePem = certificatePem,
            PrivateKeyPem = QertumKeyCodec.WritePrivateKeyPem(other.Private)
        }));

        var generator = NewGenerator(NewDirectory());
        generator.ImportCa(new ImportCaRequest
        {
            CertificatePem = certificatePem,
            PrivateKeyPem = QertumKeyCodec.WritePrivateKeyPem(keys.Private)
        });
        var leaf = QertumKeyCodec.ReadCertificatePem(generator.GenerateCertificate(
            new CertificateRequest { CommonName = "imported.composite.local" }, new CaSettings { PqcStage = PqcStage.Off }).CertificatePem)!;
        leaf.Verify(QertumKeyCodec.VerifierFor(keys.Public));
        Assert.Equal(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512, CertificateGenerator.DetectAlgorithmFromCertificatePem(certificatePem));
    }

    [Fact]
    public void ImportedCompositeRootWithoutASubjectKeyIdentifierStillGetsAnAuthorityKeyIdentifier()
    {
        var keys = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName("MLDSA44-ECDSA-P256-SHA256")!, new SecureRandom());
        var root = SelfSignedCa(keys, withSubjectKeyIdentifier: false);

        var authorityKeyIdentifier = QertumKeyCodec.AuthorityKeyIdentifierFor(root);

        Assert.Equal(
            X509ExtensionUtilities.CreateSubjectKeyIdentifier(root.CertificateStructure.SubjectPublicKeyInfo).GetKeyIdentifier(),
            authorityKeyIdentifier.KeyIdentifier.GetOctets());
    }

    [Fact]
    public void AuthorityKeyIdentifierForAClassicalIssuerIsWhatBouncyCastleBuilds()
    {
        var rsaRoot = QertumKeyCodec.ReadCertificatePem(NewRoot(CertificateKeyAlgorithm.Rsa).GetCaCertificatePem())!;

        Assert.Equal(X509ExtensionUtilities.CreateAuthorityKeyIdentifier(rsaRoot), QertumKeyCodec.AuthorityKeyIdentifierFor(rsaRoot));
    }

    private CertificateGenerator NewRoot(CertificateKeyAlgorithm algorithm)
    {
        var generator = NewGenerator(NewDirectory());
        generator.GenerateCa(new GenerateCaRequest { CommonName = $"{algorithm} Root", KeyAlgorithm = algorithm, ValidityDays = 365 });
        return generator;
    }

    private CertificateGenerator NewGenerator(string directory) =>
        new(_dataProtection, new CaDataOptions { Directory = directory }, NullLogger<CertificateGenerator>.Instance);

    private string NewDirectory()
    {
        var directory = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        _directories.Add(directory);
        return directory;
    }

    private static X509Certificate SelfSignedCa(Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair keys, bool withSubjectKeyIdentifier)
    {
        var name = new X509Name("CN=Imported Composite Root");
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(BigInteger.One);
        generator.SetIssuerDN(name);
        generator.SetSubjectDN(name);
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(30));
        generator.SetSubjectPublicKeyInfo(QertumKeyCodec.ToSubjectPublicKeyInfo(keys.Public));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        if (withSubjectKeyIdentifier)
            generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, QertumKeyCodec.SubjectKeyIdentifierFor(keys.Public));
        return generator.Generate(QertumKeyCodec.SignatureFactoryFor(keys.Private));
    }
}
