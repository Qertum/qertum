using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Crypto.Composite;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;

namespace Qertum.Tests.Crypto;

/// <summary>
/// PKCS#12 is written by <see cref="QertumKeyCodec.ExportPkcs12"/> for every algorithm. The classical
/// exports replaced the BCL's and must stay importable where they were — the .NET loader here, and
/// OpenSSL 3 when it is installed. A composite export must carry its key intact, even though no
/// mainstream tool can import that key yet.
/// </summary>
public sealed class Pkcs12ExportTests
{
    private const string Password = "pfx-test-password";
    private static readonly SecureRandom Random = new();

    public static TheoryData<string> ClassicalAlgorithms => ["RSA", "ECDSA-P256"];

    [Theory]
    [MemberData(nameof(ClassicalAlgorithms))]
    public void ClassicalExportImportsIntoDotNetWithAUsableKeyAndTheChain(string algorithm)
    {
        var (certificatePem, keyPem, caPem) = Issue(Generate(algorithm));

        var pfx = QertumKeyCodec.ExportPkcs12(certificatePem, keyPem, [caPem], Password, "leaf.contoso.local");

        var collection = X509CertificateLoader.LoadPkcs12Collection(pfx, Password);
        Assert.Equal(2, collection.Count);
        using var leaf = Assert.Single(collection, c => c.HasPrivateKey);
        using var key = (System.Security.Cryptography.AsymmetricAlgorithm?)leaf.GetRSAPrivateKey() ?? leaf.GetECDsaPrivateKey();
        Assert.NotNull(key);
    }

    [Fact]
    public void KeyAndLeafCertificateCarryTheSameLocalKeyId()
    {
        // Windows pairs a key with its certificate by localKeyId; without a match it imports a
        // certificate with no private key.
        var (certificatePem, keyPem, caPem) = Issue(Generate("RSA"));
        var pfx = QertumKeyCodec.ExportPkcs12(certificatePem, keyPem, [caPem], Password, "leaf.contoso.local");

        var authenticatedSafe = AuthenticatedSafe.GetInstance(
            Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(Pfx.GetInstance(pfx).AuthSafe.Content).GetOctets());
        var localKeyIds = authenticatedSafe.GetContentInfo()
            .SelectMany(content => Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(
                Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(content.Content).GetOctets()))
            .Select(SafeBag.GetInstance)
            .Where(bag => bag.BagAttributes is not null)
            .Select(bag => bag.BagAttributes.Cast<Org.BouncyCastle.Asn1.Asn1Encodable>()
                .Select(Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance)
                .Single(attribute => attribute[0].Equals(PkcsObjectIdentifiers.Pkcs9AtLocalKeyID)))
            .Select(attribute => Org.BouncyCastle.Asn1.Asn1Set.GetInstance(attribute[1])[0])
            .ToList();

        Assert.Equal(2, localKeyIds.Count); // the key bag and the leaf certificate, not the CA
        Assert.Equal(localKeyIds[0], localKeyIds[1]);
    }

    [Fact]
    public void WrongPasswordIsRefused()
    {
        var (certificatePem, keyPem, _) = Issue(Generate("ECDSA-P256"));
        var pfx = QertumKeyCodec.ExportPkcs12(certificatePem, keyPem, [], Password, "leaf");

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => X509CertificateLoader.LoadPkcs12Collection(pfx, "not-the-password"));
    }

    [Fact]
    public void EmptyPasswordExportsAndImports()
    {
        var (certificatePem, keyPem, _) = Issue(Generate("RSA"));

        var pfx = QertumKeyCodec.ExportPkcs12(certificatePem, keyPem, [], password: null, "leaf");

        Assert.True(X509CertificateLoader.LoadPkcs12Collection(pfx, string.Empty).Single().HasPrivateKey);
    }

    [Theory]
    [InlineData("MLDSA65-ECDSA-P256-SHA512")]
    [InlineData("MLDSA87-Ed448-SHAKE256")]
    public void CompositeExportCarriesTheCompositeKeyIntact(string name)
    {
        var keys = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName(name)!, Random);
        var (certificatePem, keyPem, caPem) = Issue(keys);

        var pfx = QertumKeyCodec.ExportPkcs12(certificatePem, keyPem, [caPem], Password, "composite.contoso.local");

        var (key, certificates) = ReadPkcs12(pfx, Password);
        Assert.Equal(((CompositePrivateKey)keys.Private).GetEncoded(), Assert.IsType<CompositePrivateKey>(key).GetEncoded());
        Assert.Equal(2, certificates.Count);
    }

    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("SLH-DSA-SHA2-128F")]
    [InlineData("ML-KEM-512")]
    [InlineData("ML-KEM-768")]
    [InlineData("ML-KEM-1024")]
    public void PqcOnlyExportCarriesTheStandardEncodingOfTheKey(string algorithm)
    {
        // RFC 9881 (ML-DSA) and RFC 9909 (SLH-DSA) fix the PKCS#8 encoding of these keys; the PKCS#12
        // wrapper (RFC 7292) is algorithm-agnostic. BouncyCastle's own store reads the file back.
        var keys = Generate(algorithm);
        var (certificatePem, keyPem, caPem) = Issue(keys);

        var pfx = QertumKeyCodec.ExportPkcs12(certificatePem, keyPem, [caPem], Password, "pqc.contoso.local");

        var store = new Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(pfx), Password.ToCharArray());
        var alias = Assert.Single(store.Aliases, store.IsKeyEntry);
        Assert.Equal(
            PrivateKeyInfoFactory.CreatePrivateKeyInfo(keys.Private).GetEncoded(),
            PrivateKeyInfoFactory.CreatePrivateKeyInfo(store.GetKey(alias).Key).GetEncoded());

        var privateKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo(store.GetKey(alias).Key);
        if (algorithm.StartsWith("ML-KEM", StringComparison.Ordinal))
        {
            // The ML-KEM certificate profile's "both": SEQUENCE { seed OCTET STRING (64: d || z),
            // expandedKey OCTET STRING }.
            var both = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(privateKey.PrivateKey.GetOctets());
            Assert.Equal(64, Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(both[0]).GetOctets().Length);
        }
        else if (algorithm.StartsWith("ML-DSA", StringComparison.Ordinal))
        {
            // RFC 9881 §6 "both": SEQUENCE { seed OCTET STRING (32), expandedKey OCTET STRING }.
            var both = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(privateKey.PrivateKey.GetOctets());
            Assert.Equal(32, Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(both[0]).GetOctets().Length);
        }
        else
        {
            // RFC 9909: SLH-DSA-PrivateKey is the raw 4n-byte key, no ASN.1 wrapping (n = 16 here).
            Assert.Equal(64, privateKey.PrivateKey.GetOctets().Length);
        }
    }

    [Fact]
    public async Task PfxRouteExportsAPqcOnlyCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var (certificatePem, keyPem, _) = Issue(Generate("ML-DSA-65"));
        var id = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.CertificateRequests.Add(new Qertum.Services.CertificateRequest
            {
                Id = id,
                CommonName = "mldsa-pfx.example.com",
                Type = "WebServer",
                Status = CertificateRequestStatus.Issued,
                KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65,
                RequestedBy = "Test User",
                CertificatePem = certificatePem,
                PrivateKeyPem = keyPem,
                ValidFrom = DateTime.UtcNow.AddDays(-1),
                ValidTo = DateTime.UtcNow.AddYears(1),
                CreatedAtUtc = DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(ct);
        }

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        var response = await admin.PostAsJsonAsync($"/v1/certificate-requests/{id}/pfx",
            new ExportPfxRequest(Password, Pqc: false, IncludeChain: false), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var store = new Pkcs12StoreBuilder().Build();
        store.Load(new MemoryStream(await response.Content.ReadAsByteArrayAsync(ct)), Password.ToCharArray());
        Assert.Single(store.Aliases, store.IsKeyEntry);
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECDSA-P256")]
    [InlineData("ML-DSA-65")]
    [InlineData("SLH-DSA-SHA2-128F")]
    [InlineData("ML-KEM-768")]
    public void OpenSslReadsTheExportIncludingTheKey(string algorithm)
    {
        var openSsl = OpenSslTool.Find() ?? throw SkipException("OpenSSL 3 is not installed.");
        // OpenSSL 3.6 is the oldest tested to import a post-quantum PKCS#8 key from a PKCS#12 file.
        if (algorithm.StartsWith("ML-", StringComparison.Ordinal) || algorithm.StartsWith("SLH-", StringComparison.Ordinal))
        {
            if (!OpenSslTool.IsAtLeast(openSsl, 3, 6)) throw SkipException("OpenSSL 3.6 or newer is needed to import a post-quantum key.");
        }
        var (certificatePem, keyPem, caPem) = Issue(Generate(algorithm));
        var path = Path.Combine(Path.GetTempPath(), $"qertum-{Guid.NewGuid():N}.pfx");
        File.WriteAllBytes(path, QertumKeyCodec.ExportPkcs12(certificatePem, keyPem, [caPem], Password, "leaf"));
        try
        {
            var (exitCode, output) = OpenSslTool.Run(openSsl, $"pkcs12 -in {path} -passin pass:{Password} -noenc");

            Assert.True(exitCode == 0, output);
            Assert.Contains("-----BEGIN PRIVATE KEY-----", output, StringComparison.Ordinal);
            Assert.Equal(2, output.Split("-----BEGIN CERTIFICATE-----").Length - 1);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task PfxRouteExportsACompositeCertificate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var keys = CompositeKeyPairGenerator.Generate(CompositeAlgorithms.FindByName("MLDSA65-ECDSA-P256-SHA512")!, Random);
        var (certificatePem, keyPem, _) = Issue(keys);
        var id = Guid.NewGuid();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.CertificateRequests.Add(new Qertum.Services.CertificateRequest
            {
                Id = id,
                CommonName = "composite-pfx.example.com",
                Type = "WebServer",
                Status = CertificateRequestStatus.Issued,
                KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512,
                RequestedBy = "Test User",
                CertificatePem = certificatePem,
                PrivateKeyPem = keyPem,
                ValidFrom = DateTime.UtcNow.AddDays(-1),
                ValidTo = DateTime.UtcNow.AddYears(1),
                CreatedAtUtc = DateTime.UtcNow,
                UpdatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(ct);
        }

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        var response = await admin.PostAsJsonAsync($"/v1/certificate-requests/{id}/pfx",
            new ExportPfxRequest(Password, Pqc: false, IncludeChain: false), ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var (key, _) = ReadPkcs12(await response.Content.ReadAsByteArrayAsync(ct), Password);
        Assert.Equal(((CompositePrivateKey)keys.Private).GetEncoded(), Assert.IsType<CompositePrivateKey>(key).GetEncoded());
    }

    /// <summary>
    /// A reader for our own output. BouncyCastle's Pkcs12Store and the .NET loader both parse the key
    /// through factories that reject a composite OID, so the bags are walked by hand here.
    /// </summary>
    private static (AsymmetricKeyParameter Key, List<BcCertificate> Certificates) ReadPkcs12(byte[] pfx, string password)
    {
        var authenticatedSafe = AuthenticatedSafe.GetInstance(
            Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(Pfx.GetInstance(pfx).AuthSafe.Content).GetOctets());
        AsymmetricKeyParameter? key = null;
        var certificates = new List<BcCertificate>();
        foreach (var content in authenticatedSafe.GetContentInfo())
        {
            var bags = Org.BouncyCastle.Asn1.Asn1Sequence.GetInstance(
                Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(content.Content).GetOctets());
            foreach (var bag in bags.Select(SafeBag.GetInstance))
            {
                if (bag.BagID.Equals(PkcsObjectIdentifiers.Pkcs8ShroudedKeyBag))
                {
                    var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(password.ToCharArray(),
                        EncryptedPrivateKeyInfo.GetInstance(bag.BagValue));
                    var pem = "-----BEGIN PRIVATE KEY-----\n" + Convert.ToBase64String(keyInfo.GetEncoded()) + "\n-----END PRIVATE KEY-----\n";
                    key = QertumKeyCodec.ReadPrivateKeyPem(pem);
                }
                else if (bag.BagID.Equals(PkcsObjectIdentifiers.CertBag))
                {
                    var certBag = CertBag.GetInstance(bag.BagValue);
                    certificates.Add(new X509CertificateParser().ReadCertificate(
                        Org.BouncyCastle.Asn1.Asn1OctetString.GetInstance(certBag.CertValue).GetOctets()));
                }
            }
        }

        return (key ?? throw new InvalidOperationException("The PFX holds no key."), certificates);
    }

    private static (string CertificatePem, string KeyPem, string CaPem) Issue(AsymmetricCipherKeyPair keys)
    {
        var ca = Generate("RSA");
        var caCertificate = Certificate("CN=Test CA", ca.Public, ca.Private, isCa: true);
        var leaf = Certificate("CN=leaf.contoso.local", keys.Public, ca.Private, isCa: false, issuer: "CN=Test CA");
        return (QertumKeyCodec.WriteCertificatePem(leaf), QertumKeyCodec.WritePrivateKeyPem(keys.Private),
            QertumKeyCodec.WriteCertificatePem(caCertificate));
    }

    private static BcCertificate Certificate(string subject, AsymmetricKeyParameter publicKey, AsymmetricKeyParameter signingKey,
        bool isCa, string? issuer = null)
    {
        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(new BigInteger(64, Random));
        generator.SetIssuerDN(new X509Name(issuer ?? subject));
        generator.SetSubjectDN(new X509Name(subject));
        generator.SetNotBefore(DateTime.UtcNow.AddMinutes(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddDays(30));
        generator.SetSubjectPublicKeyInfo(QertumKeyCodec.ToSubjectPublicKeyInfo(publicKey));
        generator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(isCa));
        return generator.Generate(QertumKeyCodec.SignatureFactoryFor(signingKey));
    }

    private static AsymmetricCipherKeyPair Generate(string algorithm)
    {
        IAsymmetricCipherKeyPairGenerator generator;
        KeyGenerationParameters parameters;
        switch (algorithm)
        {
            case "RSA":
                (generator, parameters) = (new RsaKeyPairGenerator(), new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), Random, 2048, 100));
                break;
            case "ECDSA-P256":
                (generator, parameters) = (new ECKeyPairGenerator(), new ECKeyGenerationParameters(ECNamedCurveTable.GetOid("P-256"), Random));
                break;
            case "ML-DSA-44":
                (generator, parameters) = (new MLDsaKeyPairGenerator(), new MLDsaKeyGenerationParameters(Random, MLDsaParameters.ml_dsa_44));
                break;
            case "ML-DSA-65":
                (generator, parameters) = (new MLDsaKeyPairGenerator(), new MLDsaKeyGenerationParameters(Random, MLDsaParameters.ml_dsa_65));
                break;
            case "SLH-DSA-SHA2-128F":
                (generator, parameters) = (new SlhDsaKeyPairGenerator(), new SlhDsaKeyGenerationParameters(Random, SlhDsaParameters.slh_dsa_sha2_128f));
                break;
            case "ML-KEM-512":
                (generator, parameters) = (new MLKemKeyPairGenerator(), new MLKemKeyGenerationParameters(Random, MLKemParameters.ml_kem_512));
                break;
            case "ML-KEM-768":
                (generator, parameters) = (new MLKemKeyPairGenerator(), new MLKemKeyGenerationParameters(Random, MLKemParameters.ml_kem_768));
                break;
            case "ML-KEM-1024":
                (generator, parameters) = (new MLKemKeyPairGenerator(), new MLKemKeyGenerationParameters(Random, MLKemParameters.ml_kem_1024));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(algorithm));
        }

        generator.Init(parameters);
        return generator.GenerateKeyPair();
    }

    private static Exception SkipException(string reason)
    {
        Assert.Skip(reason);
        return new InvalidOperationException(reason);
    }
}
