using System.Security.Cryptography.X509Certificates;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Crypto;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests;

// No [Collection] attribute: each test instance gets a fresh unique temp directory so
// these tests never conflict with the Aspire integration fixture, which creates CA files
// in the same AppContext.BaseDirectory when running under DistributedApplicationTestingBuilder.
public sealed class CertificateGeneratorTests : IDisposable
{
    private readonly CertificateGenerator _generator;
    private readonly string _caDataDir;

    public CertificateGeneratorTests()
    {
        // Each instance uses an isolated temp directory. The Aspire integration fixture
        // creates real CA files in <test-bin-dir>/CaData while its services are running,
        // so a shared static path caused an IOException when the old constructor tried to
        // Directory.Delete while the Aspire process still held ca.pem open.
        _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));

        var caDataOptions = new CaDataOptions { Directory = _caDataDir };
        _generator = new CertificateGenerator(new EphemeralDataProtectionProvider(), caDataOptions, NullLogger<CertificateGenerator>.Instance);

        _generator.GenerateCa(new GenerateCaRequest { CommonName = "Test Root CA", KeyAlgorithm = CertificateKeyAlgorithm.Rsa, ValidityDays = 365 });
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public void GenerateCertificate_WithSan_IncludesSanExtension()
    {
        var request = new CertificateRequest
        {
            CommonName = "san.contoso.local",
            Type = "WebServer",
            PropertiesJson = "{\"DnsNames\":[\"alt1.contoso.local\", \"alt2.contoso.local\"]}"
        };
        var settings = new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" };

        var certData = _generator.GenerateCertificate(request, settings);

        using var leafCert = X509Certificate2.CreateFromPem(certData.CertificatePem, certData.PrivateKeyPem);

        var sanExtension = leafCert.Extensions
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        Assert.NotNull(sanExtension);

        var sanString = sanExtension.Format(false);
        Assert.Contains("alt1.contoso.local", sanString);
        Assert.Contains("alt2.contoso.local", sanString);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.EcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP384)]
    public void GenerateCertificate_EcdsaAlgorithms_IssueValidLeafCert(CertificateKeyAlgorithm keyAlgorithm)
    {
        var request = new CertificateRequest
        {
            CommonName = $"ecdsa-{keyAlgorithm.ToCanonicalString().ToLower()}.contoso.local",
            Type = "WebServer",
            KeyAlgorithm = keyAlgorithm
        };
        var settings = new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" };

        var certData = _generator.GenerateCertificate(request, settings);

        Assert.NotNull(certData.CertificatePem);
        Assert.NotNull(certData.PrivateKeyPem);

        using var sr = new StringReader(certData.CertificatePem);
        var bcCert = (Org.BouncyCastle.X509.X509Certificate)
            new Org.BouncyCastle.OpenSsl.PemReader(sr).ReadObject();

        Assert.Contains($"ecdsa-{keyAlgorithm.ToCanonicalString().ToLowerInvariant()}.contoso.local", bcCert.SubjectDN.ToString());

        var pubKey = bcCert.GetPublicKey();
        var ecKey = Assert.IsType<Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters>(pubKey);

        var expectedBitLength = keyAlgorithm == CertificateKeyAlgorithm.EcdsaP384 ? 384 : 256;
        Assert.Equal(expectedBitLength, ecKey.Parameters.N.BitLength);
    }

    // Leaf issuance for the PQC algorithms, under the suite's RSA CA — a classical issuer signing
    // a post-quantum subject key, which is the realistic deployment shape. These assert on the
    // issued certificate's own public key, so they fail if BuildSingleCertificate ever selects the
    // wrong ICertificateAlgorithmStrategy for the request's algorithm.
    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    public void GenerateCertificate_MlDsaAlgorithms_IssueALeafCarryingThatExactParameterSet(string canonical)
    {
        var algorithm = CertificateKeyAlgorithmExtensions.Parse(canonical)!.Value;
        var request = new CertificateRequest
        {
            CommonName = $"{canonical.ToLowerInvariant()}.contoso.local",
            Type = "WebServer",
            KeyAlgorithm = algorithm
        };

        var certData = _generator.GenerateCertificate(request, new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

        var bcCert = ReadCertificate(certData.CertificatePem);
        var pubKey = Assert.IsType<Org.BouncyCastle.Crypto.Parameters.MLDsaPublicKeyParameters>(bcCert.GetPublicKey());
        Assert.Equal(algorithm, CertificateGenerator.DetectAlgorithmFromCertificatePem(certData.CertificatePem));
        Assert.Equal(canonical, pubKey.Parameters.Name.ToUpperInvariant().Replace("_", "-"));
        Assert.NotEmpty(certData.PrivateKeyPem);
    }

    [Theory]
    [InlineData("SLH-DSA-SHA2-128S")]
    [InlineData("SLH-DSA-SHA2-128F")]
    [InlineData("SLH-DSA-SHA2-192S")]
    [InlineData("SLH-DSA-SHA2-192F")]
    [InlineData("SLH-DSA-SHA2-256S")]
    [InlineData("SLH-DSA-SHA2-256F")]
    public void GenerateCertificate_SlhDsaAlgorithms_IssueALeafCarryingThatExactParameterSet(string canonical)
    {
        var algorithm = CertificateKeyAlgorithmExtensions.Parse(canonical)!.Value;
        var request = new CertificateRequest
        {
            CommonName = $"{canonical.ToLowerInvariant()}.contoso.local",
            Type = "WebServer",
            KeyAlgorithm = algorithm
        };

        var certData = _generator.GenerateCertificate(request, new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

        var bcCert = ReadCertificate(certData.CertificatePem);
        Assert.IsType<Org.BouncyCastle.Crypto.Parameters.SlhDsaPublicKeyParameters>(bcCert.GetPublicKey());
        // The SLH-DSA sets of one level share a public key size, so only the detected algorithm
        // separates them — asserting on the key alone would pass for either.
        Assert.Equal(algorithm, CertificateGenerator.DetectAlgorithmFromCertificatePem(certData.CertificatePem));
        Assert.NotEmpty(certData.PrivateKeyPem);
    }

    // An SLH-DSA *subject* key is only 32 bytes, so a leaf carrying one under a classical issuer
    // is small — smaller than an ML-DSA leaf, whose public key is around 1.9 KB. The size cost of
    // SLH-DSA lands on whatever it signs, not on the certificate that holds its public key.
    [Fact]
    public void GenerateCertificate_SlhDsaLeafUnderAClassicalCa_StaysSmall()
    {
        var request = new CertificateRequest
        {
            CommonName = "slh-subject.contoso.local",
            Type = "WebServer",
            KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse("SLH-DSA-SHA2-128S")!.Value
        };

        var certData = _generator.GenerateCertificate(request, new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

        var leaf = ReadCertificate(certData.CertificatePem);
        Assert.True(leaf.GetEncoded().Length < 2000,
            $"expected a small leaf under the RSA CA, got {leaf.GetEncoded().Length} bytes");
        leaf.Verify(ReadCertificate(_generator.GetCaCertificatePem()).GetPublicKey());
    }

    // The case that makes certificate size matter: when SLH-DSA is the *issuer*, its
    // signature lands in every certificate it signs. Nothing else in the suite issues a leaf that
    // large, and it must still round-trip through PEM and verify against the CA.
    [Fact]
    public void GenerateCertificate_UnderAnSlhDsaCa_ProducesALargeLeafThatStillVerifies()
    {
        var caDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var slhGenerator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = caDir },
                NullLogger<CertificateGenerator>.Instance);
            slhGenerator.GenerateCa(new GenerateCaRequest
            {
                CommonName = "SLH-DSA Issuing CA",
                KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse("SLH-DSA-SHA2-128S")!.Value,
                ValidityDays = 365
            });

            var certData = slhGenerator.GenerateCertificate(
                new CertificateRequest { CommonName = "under-slh.contoso.local", Type = "WebServer" },
                new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

            var leaf = ReadCertificate(certData.CertificatePem);
            Assert.True(leaf.GetEncoded().Length > 7000,
                $"expected an SLH-DSA issuer signature to dominate the leaf, got {leaf.GetEncoded().Length} bytes");
            leaf.Verify(ReadCertificate(slhGenerator.GetCaCertificatePem()).GetPublicKey());
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }

    private static Org.BouncyCastle.X509.X509Certificate ReadCertificate(string pem)
    {
        using var reader = new StringReader(pem);
        return (Org.BouncyCastle.X509.X509Certificate)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
    }

    [Fact]
    public void CaKey_OnDisk_IsEncryptedNotPlaintextPem()
    {
        var caKeyPath = Path.Combine(_caDataDir, "ca.key");
        Assert.True(File.Exists(caKeyPath), "ca.key must exist after GenerateCa call in constructor");

        var content = File.ReadAllText(caKeyPath);
        Assert.DoesNotContain("BEGIN", content, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE KEY", content, StringComparison.Ordinal);
    }

    [Fact]
    public void GenerateCertificate_RespectsCertificateValidityDays()
    {
        var request = new CertificateRequest { CommonName = "validity-test.local" };
        var settings = new CaSettings { PqcStage = PqcStage.Off, CertificateValidityDays = 30 };

        var before = DateTime.UtcNow;
        var cert = _generator.GenerateCertificate(request, settings);
        var after = DateTime.UtcNow;

        var expectedMin = before.AddDays(30).AddMinutes(-6);
        var expectedMax = after.AddDays(30).AddMinutes(1);
        Assert.InRange(cert.ValidTo, expectedMin, expectedMax);
    }

    [Fact]
    public void GenerateCertificate_SerialNumbers_ArePositiveUniqueAndWithinTwentyOctets()
    {
        var settings = new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" };
        var serials = new List<System.Numerics.BigInteger>();

        for (var i = 0; i < 25; i++)
        {
            var certData = _generator.GenerateCertificate(
                new CertificateRequest { CommonName = $"serial-{i}.contoso.local" }, settings);

            using var leaf = X509Certificate2.CreateFromPem(certData.CertificatePem);
            var serialBytes = leaf.SerialNumberBytes.ToArray();

            // RFC 5280 §4.1.2.2: the serial must be a positive integer of at most 20 octets.
            Assert.InRange(serialBytes.Length, 8, 20);
            var serial = new System.Numerics.BigInteger(serialBytes, isUnsigned: true, isBigEndian: true);
            Assert.True(serial > 0, "Serial number must be positive.");

            // The generator reports the serial it signed, so callers do not have to re-parse the PEM.
            Assert.NotNull(certData.SerialNumber);
            var reported = System.Numerics.BigInteger.Parse(
                "0" + certData.SerialNumber, System.Globalization.NumberStyles.HexNumber);
            Assert.Equal(serial, reported);

            serials.Add(serial);
        }

        Assert.Equal(serials.Count, serials.Distinct().Count());
    }

    [Fact]
    public void GenerateCrl_RespectsConfiguredCrlValidityHours()
    {
        var settings = new CaSettings { PqcStage = PqcStage.Off, CrlValidityHours = 48 };
        var before = DateTime.UtcNow;
        var crlBytes = _generator.GenerateCrl([], settings);
        var after = DateTime.UtcNow;

        using var ms = new MemoryStream(crlBytes);
        var bcCrl = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(ms);

        var nextUpdate = bcCrl.NextUpdate;
        Assert.NotNull(nextUpdate);
        var expectedMin = before.AddHours(48).AddMinutes(-1);
        var expectedMax = after.AddHours(48).AddMinutes(1);
        Assert.InRange(nextUpdate.Value, expectedMin, expectedMax);
    }

    [Fact]
    public void DetectAlgorithmFromCertificatePem_ReturnsRsaForRsaCa()
    {
        var pem = _generator.GetCaCertificatePem(); // constructor generated an Rsa CA

        var detected = CertificateGenerator.DetectAlgorithmFromCertificatePem(pem);

        Assert.Equal(CertificateKeyAlgorithm.Rsa, detected);
    }

    [Fact]
    public void DetectAlgorithmFromCertificatePem_ReturnsMlDsa65ForMlDsaCa()
    {
        var mlDsaDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var mlDsaGenerator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = mlDsaDir },
                NullLogger<CertificateGenerator>.Instance);
            mlDsaGenerator.GenerateCa(new GenerateCaRequest
            {
                CommonName = "PQC Test Root CA",
                KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65,
                ValidityDays = 365
            });

            var detected = CertificateGenerator.DetectAlgorithmFromCertificatePem(mlDsaGenerator.GetCaCertificatePem());

            Assert.Equal(CertificateKeyAlgorithm.MlDsa65, detected);
        }
        finally
        {
            if (Directory.Exists(mlDsaDir))
                try { Directory.Delete(mlDsaDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void DetectAlgorithmFromCertificatePem_ThrowsArgumentExceptionForGarbagePem()
    {
        Assert.Throws<ArgumentException>(() =>
            CertificateGenerator.DetectAlgorithmFromCertificatePem("not a pem"));
    }

    [Fact]
    public void DetectAlgorithmFromCsr_ReturnsMlDsa65ForMlDsaCsr()
    {
        var random = new SecureRandom();
        var strategy = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.MlDsa65);
        var keyPair = strategy.GenerateLeafKeyPair(random);
        var csr = new Pkcs10CertificationRequest(
            strategy.CaSignatureAlgorithm, new X509Name("CN=pqc.example.test"), keyPair.Public, null, keyPair.Private);
        var csrB64 = JwkConverter.Base64UrlEncode(csr.GetDerEncoded());

        var detected = CertificateGenerator.DetectAlgorithmFromCsr(csrB64);

        Assert.Equal(CertificateKeyAlgorithm.MlDsa65, detected);
    }

    [Fact]
    public void GenerateFromCsr_MlDsaRequest_OmitsEnciphermentUsageEvenWhenTheTemplateAsksForIt()
    {
        // Locks the RFC 9881 §5 property the KeyAlgorithm-detection fix exists to preserve: ML-DSA
        // is signature-only, so keyEncipherment/dataEncipherment/keyAgreement must never appear no
        // matter what the template requests. Passes against the current strategy — it guards the
        // invariant rather than driving new behavior, which is why it is a characterization test.
        var csrB64 = TestCsrBuilder.BuildMlDsaBase64Url("mldsa-usage.example.test", []);
        var template = new CertificateTemplate
        {
            TypeKey = "WebServer",
            Name = "Web Server",
            KeyUsagesJson = """["DigitalSignature","KeyEncipherment","DataEncipherment","KeyAgreement"]"""
        };
        var request = new CertificateRequest
        {
            CommonName = "mldsa-usage.example.test",
            Type = "WebServer",
            KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65,
            CsrPem = csrB64
        };

        var generated = _generator.GenerateFromCsr(csrB64, request, new CaSettings { PqcStage = PqcStage.Off }, template);

        var cert = X509Certificate2.CreateFromPem(generated.CertificatePem);
        var keyUsage = cert.Extensions.OfType<X509KeyUsageExtension>().Single();
        Assert.Equal(X509KeyUsageFlags.DigitalSignature, keyUsage.KeyUsages);
    }

    [Fact]
    public void DetectAlgorithmFromCsr_ReturnsMlDsa87ForMlDsa87Csr()
    {
        var csrB64 = TestCsrBuilder.BuildMlDsaBase64Url("pqc87.example.test", [], level5: true);

        Assert.Equal(CertificateKeyAlgorithm.MlDsa87, CertificateGenerator.DetectAlgorithmFromCsr(csrB64));
    }

    [Theory]
    [InlineData("P-256", CertificateKeyAlgorithm.EcdsaP256)]
    [InlineData("P-384", CertificateKeyAlgorithm.EcdsaP384)]
    public void DetectAlgorithmFromCsr_IdentifiesEachSupportedCurve(string curveName, CertificateKeyAlgorithm expected)
    {
        var csrB64 = TestCsrBuilder.BuildEcdsaBase64Url("ec.example.test", curveName);

        Assert.Equal(expected, CertificateGenerator.DetectAlgorithmFromCsr(csrB64));
    }

    [Fact]
    public void DetectAlgorithmFromCsr_IdentifiesMlDsa44AsItselfNotAsANeighbouringParameterSet()
    {
        // RFC 9881 standardizes ML-DSA-44/65/87 and Qertum now implements all three. Detection
        // must distinguish them: reporting a 44 key as ML-DSA-65 would persist a KeyAlgorithm the
        // certificate does not have, which is what this assertion has always been guarding.
        // Until ML-DSA-44 was implemented the same guarantee was expressed as a refusal.
        var csrB64 = TestCsrBuilder.BuildMlDsa44Base64Url("pqc44.example.test");

        Assert.Equal(CertificateKeyAlgorithm.MlDsa44, CertificateGenerator.DetectAlgorithmFromCsr(csrB64));
    }

    [Theory]
    [InlineData(false, CertificateKeyAlgorithm.MlDsa65)]
    [InlineData(true, CertificateKeyAlgorithm.MlDsa87)]
    public void DetectAlgorithmFromCsr_IdentifiesEachMlDsaParameterSet(bool level5, CertificateKeyAlgorithm expected)
    {
        var csrB64 = TestCsrBuilder.BuildMlDsaBase64Url("pqc.example.test", [], level5);

        Assert.Equal(expected, CertificateGenerator.DetectAlgorithmFromCsr(csrB64));
    }

    [Fact]
    public void DetectAlgorithmFromCsr_RefusesUnsupportedKeyTypeRatherThanReportingItRsa()
    {
        var csrB64 = TestCsrBuilder.BuildEd25519Base64Url("ed25519.example.test");

        Assert.Throws<NotSupportedException>(() => CertificateGenerator.DetectAlgorithmFromCsr(csrB64));
    }

    [Fact]
    public void ValidateImportAlgorithmPolicy_RejectsUnsupportedKeyTypeWithBadRequest()
    {
        // The helper detects unconditionally, so an unsupported key type must surface as a 400
        // from its own catch rather than escaping as an unhandled exception (a 500).
        var pem = TestCertificates.CreateSelfSignedEd25519Pem("CN=Ed25519 Root");

        var result = ApiEndpointMappings.ValidateImportAlgorithmPolicy(new CaSettings { PqcStage = PqcStage.Off }, pem);

        Assert.NotNull(result);
    }

    [Fact]
    public void DetectAlgorithmFromCsr_ThrowsForGarbageInput()
    {
        // Base64Url-valid but not a real DER CSR: BouncyCastle's ASN.1 parser rejects it with
        // ArgumentException rather than the FormatException a decode failure would give.
        Assert.Throws<ArgumentException>(() =>
            CertificateGenerator.DetectAlgorithmFromCsr("not-a-real-csr"));
    }

    [Fact]
    public void ValidateImportAlgorithmPolicy_AtEnforce_RejectsRsaCertificate()
    {
        var settings = new CaSettings { PqcStage = PqcStage.Enforce };
        var rsaPem = _generator.GetCaCertificatePem();

        var result = ApiEndpointMappings.ValidateImportAlgorithmPolicy(settings, rsaPem);

        Assert.NotNull(result);
    }

    [Fact]
    public void ValidateImportAlgorithmPolicy_AtEnforce_AllowsMlDsaCertificate()
    {
        var mlDsaDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var mlDsaGenerator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = mlDsaDir },
                NullLogger<CertificateGenerator>.Instance);
            mlDsaGenerator.GenerateCa(new GenerateCaRequest
            {
                CommonName = "PQC Test Root CA",
                KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65,
                ValidityDays = 365
            });

            var settings = new CaSettings { PqcStage = PqcStage.Enforce };
            var result = ApiEndpointMappings.ValidateImportAlgorithmPolicy(settings, mlDsaGenerator.GetCaCertificatePem());

            Assert.Null(result);
        }
        finally
        {
            if (Directory.Exists(mlDsaDir))
                try { Directory.Delete(mlDsaDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Theory]
    [InlineData(PqcStage.Off)]
    [InlineData(PqcStage.Observe)]
    [InlineData(PqcStage.Warn)]
    public void ValidateImportAlgorithmPolicy_BelowPilot_AllowsRsaCertificate(PqcStage stage)
    {
        var result = ApiEndpointMappings.ValidateImportAlgorithmPolicy(
            new CaSettings { PqcStage = stage }, _generator.GetCaCertificatePem());

        Assert.Null(result);
    }

    [Fact]
    public void ValidateImportAlgorithmPolicy_AtPilot_RejectsRsaCertificate()
    {
        var result = ApiEndpointMappings.ValidateImportAlgorithmPolicy(
            new CaSettings { PqcStage = PqcStage.Pilot }, _generator.GetCaCertificatePem());

        Assert.NotNull(result);
    }

    [Fact]
    public void ValidateImportAlgorithmPolicy_PolicyDisabled_AllowsRsaCertificate()
    {
        var settings = new CaSettings { PqcStage = PqcStage.Off };
        var rsaPem = _generator.GetCaCertificatePem();

        var result = ApiEndpointMappings.ValidateImportAlgorithmPolicy(settings, rsaPem);

        Assert.Null(result);
    }
    // Paired issuance signs two certificates, each with its own serial. Both must be reported so
    // both can be indexed, looked up by OCSP and listed on the CRL once the pair is revoked.
    [Fact]
    public void GenerateCertificate_Hybrid_ReportsTheSerialOfEachCertificate()
    {
        var request = new CertificateRequest
        {
            CommonName = "paired.contoso.local",
            KeyAlgorithm = CertificateKeyAlgorithm.HybridEcdsaP256
        };

        var generated = _generator.GenerateCertificate(request, new CaSettings { PqcStage = PqcStage.Off });

        Assert.Equal(SerialHex(ReadCertificate(generated.CertificatePem)), generated.SerialNumber);
        Assert.NotNull(generated.PqcCertificatePem);
        Assert.Equal(SerialHex(ReadCertificate(generated.PqcCertificatePem!)), generated.PqcSerialNumber);
        Assert.NotEqual(generated.SerialNumber, generated.PqcSerialNumber);
    }

    [Fact]
    public void GenerateCertificate_NotHybrid_ReportsNoPqcSerial()
    {
        var generated = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "single.contoso.local", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65 },
            new CaSettings { PqcStage = PqcStage.Off });

        Assert.Null(generated.PqcSerialNumber);
    }

    // A revoked pair is revoked as a whole. Listing only the classical serial left the PQC
    // certificate looking valid to every relying party that checks the CRL.
    [Fact]
    public void GenerateCrl_RevokedHybridRequest_ListsBothCertificates()
    {
        var generated = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "revoked-pair.contoso.local", KeyAlgorithm = CertificateKeyAlgorithm.HybridEcdsaP384 },
            new CaSettings { PqcStage = PqcStage.Off });
        var revoked = new CertificateRequest
        {
            CommonName = "revoked-pair.contoso.local",
            Status = CertificateRequestStatus.Revoked,
            KeyAlgorithm = CertificateKeyAlgorithm.PairMlDsa65MlKem768,
            CertificatePem = generated.CertificatePem,
            PqcCertificatePem = generated.PqcCertificatePem,
            RevokedAtUtc = DateTime.UtcNow.AddHours(-1),
            RevocationReason = "keyCompromise"
        };

        var full = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(_generator.GenerateCrl([revoked], new CaSettings { PqcStage = PqcStage.Off }));
        var delta = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(
            _generator.GenerateDeltaCrl([revoked], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2, baseCrlNumber: 1));

        foreach (var crl in new[] { full, delta })
        {
            Assert.NotNull(crl.GetRevokedCertificate(ReadCertificate(generated.CertificatePem).SerialNumber));
            Assert.NotNull(crl.GetRevokedCertificate(ReadCertificate(generated.PqcCertificatePem!).SerialNumber));
        }
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa44MlKem512, "2.16.840.1.101.3.4.3.17", "2.16.840.1.101.3.4.4.1")]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768, "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.4.2")]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa87MlKem1024, "2.16.840.1.101.3.4.3.19", "2.16.840.1.101.3.4.4.3")]
    public void GenerateCertificate_Pair_IssuesASigningAndAnEncryptionCertificate(
        CertificateKeyAlgorithm algorithm, string signingKeyOid, string encryptionKeyOid)
    {
        var generated = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "pair.contoso.local", KeyAlgorithm = algorithm, Type = "SMIME" },
            new CaSettings { PqcStage = PqcStage.Off });

        // Never one certificate alone: both legs, both keys, both serials.
        Assert.False(string.IsNullOrWhiteSpace(generated.CertificatePem));
        Assert.False(string.IsNullOrWhiteSpace(generated.PrivateKeyPem));
        Assert.False(string.IsNullOrWhiteSpace(generated.PqcCertificatePem));
        Assert.False(string.IsNullOrWhiteSpace(generated.PqcPrivateKeyPem));
        var signing = ReadCertificate(generated.CertificatePem);
        var encryption = ReadCertificate(generated.PqcCertificatePem!);
        Assert.Equal(SerialHex(signing), generated.SerialNumber);
        Assert.Equal(SerialHex(encryption), generated.PqcSerialNumber);
        Assert.NotEqual(generated.SerialNumber, generated.PqcSerialNumber);

        Assert.Equal(signingKeyOid, signing.SubjectPublicKeyInfo.Algorithm.Algorithm.Id);
        Assert.Equal(encryptionKeyOid, encryption.SubjectPublicKeyInfo.Algorithm.Algorithm.Id);

        // The encryption certificate can only encipher keys; the signing one can sign.
        var encryptionUsage = encryption.GetKeyUsage()!;
        Assert.True(encryptionUsage[2], "keyEncipherment");
        Assert.False(encryptionUsage[0], "digitalSignature");
        Assert.True(signing.GetKeyUsage()![0], "digitalSignature");

        // One validity window for the pair.
        Assert.Equal(signing.NotBefore, encryption.NotBefore);
        Assert.Equal(signing.NotAfter, encryption.NotAfter);
        Assert.Equal(generated.ValidFrom, signing.NotBefore, TimeSpan.FromSeconds(2));
        Assert.Equal(generated.ValidTo, signing.NotAfter, TimeSpan.FromSeconds(2));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768)]
    public void GenerateFromCsr_RefusesAnyPairedAlgorithm(CertificateKeyAlgorithm algorithm)
    {
        // A CSR proves one key; a pair is two, and a KEM key cannot sign a CSR at all.
        Assert.Throws<NotSupportedException>(() => _generator.GenerateFromCsr(
            "ignored", new CertificateRequest { CommonName = "csr.contoso.local", KeyAlgorithm = algorithm },
            new CaSettings { PqcStage = PqcStage.Off }));
    }

    // A revoked pair is revoked as a whole: the encryption certificate must not look valid on the CRL.
    [Fact]
    public void GenerateCrl_RevokedPairRequest_ListsBothCertificates_OnTheFullAndTheDeltaCrl()
    {
        var generated = _generator.GenerateCertificate(
            new CertificateRequest { CommonName = "revoked-mail-pair.contoso.local", KeyAlgorithm = CertificateKeyAlgorithm.PairMlDsa65MlKem768 },
            new CaSettings { PqcStage = PqcStage.Off });
        var revoked = new CertificateRequest
        {
            CommonName = "revoked-mail-pair.contoso.local",
            Status = CertificateRequestStatus.Revoked,
            CertificatePem = generated.CertificatePem,
            PqcCertificatePem = generated.PqcCertificatePem,
            RevokedAtUtc = DateTime.UtcNow.AddHours(-1),
            RevocationReason = "keyCompromise"
        };

        var full = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(_generator.GenerateCrl([revoked], new CaSettings { PqcStage = PqcStage.Off }));
        var delta = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(
            _generator.GenerateDeltaCrl([revoked], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2, baseCrlNumber: 1));

        foreach (var crl in new[] { full, delta })
        {
            Assert.NotNull(crl.GetRevokedCertificate(ReadCertificate(generated.CertificatePem).SerialNumber));
            Assert.NotNull(crl.GetRevokedCertificate(ReadCertificate(generated.PqcCertificatePem!).SerialNumber));
        }
    }

    private static string SerialHex(Org.BouncyCastle.X509.X509Certificate certificate) =>
        certificate.SerialNumber.ToString(16).ToUpperInvariant();
}
