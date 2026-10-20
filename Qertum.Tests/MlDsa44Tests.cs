using System.CommandLine;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Crypto;

namespace Qertum.Tests;

/// <summary>
/// ML-DSA-44 (FIPS 204 level 2). Driven through the canonical-string API rather than the enum
/// member so the suite compiles against the pre-change code and fails at runtime, which is what
/// makes the RED step meaningful here.
/// </summary>
public sealed class MlDsa44Tests
{
    private static CertificateKeyAlgorithm MlDsa44 =>
        CertificateKeyAlgorithmExtensions.Parse("ML-DSA-44")
        ?? throw new InvalidOperationException("ML-DSA-44 is not a recognised algorithm.");

    [Fact]
    public void Parse_RoundTripsMlDsa44ThroughItsCanonicalString()
    {
        Assert.Equal("ML-DSA-44", MlDsa44.ToCanonicalString());
    }

    [Fact]
    public void MlDsa44_BelongsToThePqcFamily()
    {
        Assert.Equal(AlgorithmFamily.Pqc, MlDsa44.GetFamily());
    }

    // The regression this whole change hinges on: MlDsaAlgorithmStrategy selected its parameter
    // set with `algorithm == MlDsa87 ? ml_dsa_87 : ml_dsa_65`, so a third value silently produced
    // an ML-DSA-65 key under an ML-DSA-44 label.
    [Fact]
    public void GenerateLeafKeyPair_ForMlDsa44_ActuallyUsesTheMlDsa44ParameterSet()
    {
        var strategy = AlgorithmStrategyFactory.Create(MlDsa44);

        var keyPair = strategy.GenerateLeafKeyPair(new SecureRandom());

        var publicKey = Assert.IsType<MLDsaPublicKeyParameters>(keyPair.Public);
        Assert.Equal(MLDsaParameters.ml_dsa_44, publicKey.Parameters);
    }

    [Fact]
    public void CaSignatureAlgorithm_ForMlDsa44_IsNotLabelledAsAnotherParameterSet()
    {
        Assert.Equal("ML-DSA-44", AlgorithmStrategyFactory.CreateIssuer(MlDsa44).CaSignatureAlgorithm);
    }

    // The mirrored ternary in AlgorithmStrategyFactory.CreateFromPrivateKey.
    [Fact]
    public void CreateFromPrivateKey_ForAnMlDsa44Key_KeepsTheMlDsa44ParameterSet()
    {
        var keyPair = AlgorithmStrategyFactory.Create(MlDsa44).GenerateLeafKeyPair(new SecureRandom());

        var strategy = AlgorithmStrategyFactory.CreateFromPrivateKey(keyPair.Private);

        Assert.Equal("ML-DSA-44", strategy.CaSignatureAlgorithm);
    }

    [Fact]
    public void GenerateCa_WithMlDsa44_ProducesAnMlDsa44RootCertificate()
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
                CommonName = "ML-DSA-44 Test Root CA",
                KeyAlgorithm = MlDsa44,
                ValidityDays = 365
            });

            Assert.Equal(MlDsa44,
                CertificateGenerator.DetectAlgorithmFromCertificatePem(generator.GetCaCertificatePem()));
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }

    [Fact]
    public void CliRequestsCreate_AcceptsMlDsa44AsAKeyAlgorithm()
    {
        var command = Qertum.Cli.Commands.RequestsCommands.Build(
            new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
            new Option<string?>("--token"), new Option<string>("--output"));

        var result = command.Parse("create -n mldsa44.example.test -k ML-DSA-44");

        Assert.Empty(result.Errors);
    }

    [Fact]
    public void EnrollmentWizard_OffersMlDsa44AsAPqcChoice()
    {
        var choice = Assert.Single(
            Qertum.Web.Components.Pages.Enrollment.AlgorithmChoices.All,
            a => a.Value == "ML-DSA-44");

        Assert.Equal(Qertum.Web.Components.Pages.Enrollment.AlgorithmKind.Pqc, choice.Kind);
    }
}
