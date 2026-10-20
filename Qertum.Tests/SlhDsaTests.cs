using System.CommandLine;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Crypto;

namespace Qertum.Tests;

/// <summary>
/// SLH-DSA (FIPS 205), SHA2-128S and SHA2-128F. Driven through the canonical-string API so the
/// suite compiles against the pre-change code and fails at runtime.
/// </summary>
public sealed class SlhDsaTests
{
    private const string Sha2128S = "SLH-DSA-SHA2-128S";
    private const string Sha2128F = "SLH-DSA-SHA2-128F";

    private static CertificateKeyAlgorithm Algorithm(string canonical) =>
        CertificateKeyAlgorithmExtensions.Parse(canonical)
        ?? throw new InvalidOperationException($"{canonical} is not a recognised algorithm.");

    [Theory]
    [InlineData(Sha2128S)]
    [InlineData(Sha2128F)]
    public void Parse_RoundTripsEachSetThroughItsCanonicalString(string canonical)
    {
        Assert.Equal(canonical, Algorithm(canonical).ToCanonicalString());
    }

    [Theory]
    [InlineData(Sha2128S)]
    [InlineData(Sha2128F)]
    public void SlhDsa_BelongsToThePqcFamily(string canonical)
    {
        Assert.Equal(AlgorithmFamily.Pqc, Algorithm(canonical).GetFamily());
    }

    // 128s and 128f differ only by parameter set — both have 32-byte public keys — so a strategy
    // that defaulted to one of them would be invisible by inspection.
    [Fact]
    public void GenerateLeafKeyPair_Uses128sParametersFor128s()
    {
        var keyPair = AlgorithmStrategyFactory.Create(Algorithm(Sha2128S)).GenerateLeafKeyPair(new SecureRandom());

        var publicKey = Assert.IsType<SlhDsaPublicKeyParameters>(keyPair.Public);
        Assert.Equal(SlhDsaParameters.slh_dsa_sha2_128s, publicKey.Parameters);
    }

    [Fact]
    public void GenerateLeafKeyPair_Uses128fParametersFor128f()
    {
        var keyPair = AlgorithmStrategyFactory.Create(Algorithm(Sha2128F)).GenerateLeafKeyPair(new SecureRandom());

        var publicKey = Assert.IsType<SlhDsaPublicKeyParameters>(keyPair.Public);
        Assert.Equal(SlhDsaParameters.slh_dsa_sha2_128f, publicKey.Parameters);
    }

    [Theory]
    [InlineData(Sha2128S)]
    [InlineData(Sha2128F)]
    public void CaSignatureAlgorithm_NamesTheSetItActuallyUses(string canonical)
    {
        Assert.Equal(canonical, AlgorithmStrategyFactory.CreateIssuer(Algorithm(canonical)).CaSignatureAlgorithm);
    }

    [Theory]
    [InlineData(Sha2128S)]
    [InlineData(Sha2128F)]
    public void CreateFromPrivateKey_KeepsTheOriginalParameterSet(string canonical)
    {
        var keyPair = AlgorithmStrategyFactory.Create(Algorithm(canonical)).GenerateLeafKeyPair(new SecureRandom());

        Assert.Equal(canonical, AlgorithmStrategyFactory.CreateFromPrivateKey(keyPair.Private).CaSignatureAlgorithm);
    }

    // The near-miss that matters here: the two sets are indistinguishable by key size, so
    // detection has only the algorithm OID to go on.
    [Theory]
    [InlineData(Sha2128S)]
    [InlineData(Sha2128F)]
    public void DetectAlgorithmFromCsr_DistinguishesTheTwoParameterSets(string canonical)
    {
        var expected = Algorithm(canonical);
        var strategy = AlgorithmStrategyFactory.CreateIssuer(expected);
        var keyPair = strategy.GenerateLeafKeyPair(new SecureRandom());
        var csr = new Pkcs10CertificationRequest(
            strategy.CaSignatureAlgorithm, new X509Name("CN=slhdsa.example.test"),
            keyPair.Public, null, keyPair.Private);

        var detected = CertificateGenerator.DetectAlgorithmFromCsr(
            JwkConverter.Base64UrlEncode(csr.GetDerEncoded()));

        Assert.Equal(expected, detected);
    }

    [Fact]
    public void BuildKeyUsageBits_DropsKeyExchangeBitsBecauseSlhDsaIsSignatureOnly()
    {
        var strategy = AlgorithmStrategyFactory.Create(Algorithm(Sha2128S));

        var bits = strategy.BuildKeyUsageBits(["DigitalSignature", "KeyEncipherment", "KeyAgreement"]);

        Assert.Equal(0, bits & KeyUsage.KeyEncipherment);
        Assert.Equal(0, bits & KeyUsage.KeyAgreement);
        Assert.NotEqual(0, bits & KeyUsage.DigitalSignature);
    }

    [Fact]
    public void GenerateCa_WithSlhDsa_ProducesAnSlhDsaRootCertificate()
    {
        var caDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var generator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = caDir },
                NullLogger<CertificateGenerator>.Instance);

            generator.GenerateCa(new GenerateCaRequest
            {
                CommonName = "SLH-DSA Test Root CA",
                KeyAlgorithm = Algorithm(Sha2128S),
                ValidityDays = 365
            });

            Assert.Equal(Algorithm(Sha2128S),
                CertificateGenerator.DetectAlgorithmFromCertificatePem(generator.GetCaCertificatePem()));
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Theory]
    [InlineData(Sha2128S)]
    [InlineData(Sha2128F)]
    public void CliRequestsCreate_AcceptsEachSetAsAKeyAlgorithm(string canonical)
    {
        var command = Qertum.Cli.Commands.RequestsCommands.Build(
            new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
            new Option<string?>("--token"), new Option<string>("--output"));

        var result = command.Parse($"create -n slh.example.test -k {canonical}");

        Assert.Empty(result.Errors);
    }

    [Theory]
    [InlineData(Sha2128S)]
    [InlineData(Sha2128F)]
    public void EnrollmentWizard_OffersEachSetAsAPqcChoice(string canonical)
    {
        var choice = Assert.Single(
            Qertum.Web.Components.Pages.Enrollment.AlgorithmChoices.All,
            a => a.Value == canonical);

        Assert.Equal(Qertum.Web.Components.Pages.Enrollment.AlgorithmKind.Pqc, choice.Kind);
    }
}
