using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class IssuerStrengthRuleTests
{
    private static readonly IssuancePolicyEvaluator Evaluator = new();

    private static Issuer Ca(CertificateKeyAlgorithm? algorithm, string name = "Issuing") =>
        new() { Name = name, KeyAlgorithm = algorithm };

    private static CertificateTemplate Template() => new()
    {
        TypeKey = "WebServer",
        KeyUsagesJson = "[\"DigitalSignature\"]",
        SanTypesJson = "[\"dns\"]"
    };

    private static PolicyDecision Evaluate(CertificateKeyAlgorithm? subject, CertificateKeyAlgorithm? issuer,
        IssuerStrengthMode mode)
    {
        var request = new CertificateRequest { CommonName = "www.corp.example", Type = "WebServer", KeyAlgorithm = subject };
        var settings = new CaSettings { PqcStage = PqcStage.Off, IssuerStrengthMode = mode };
        return Evaluator.Evaluate(request, Template(), null, null, settings, requester: null,
            issuerPath: [Ca(issuer)]);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.MlDsa44, 2)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65, 3)]
    [InlineData(CertificateKeyAlgorithm.MlDsa87, 5)]
    [InlineData(CertificateKeyAlgorithm.SlhDsaSha2128s, 1)]
    [InlineData(CertificateKeyAlgorithm.SlhDsaSha2192f, 3)]
    [InlineData(CertificateKeyAlgorithm.SlhDsaSha2256s, 5)]
    [InlineData(CertificateKeyAlgorithm.MlKem512, 1)]
    [InlineData(CertificateKeyAlgorithm.MlKem1024, 5)]
    [InlineData(CertificateKeyAlgorithm.MlDsa44Ed25519Sha512, 2)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65EcdsaP384Sha512, 3)]
    [InlineData(CertificateKeyAlgorithm.MlDsa87Rsa4096PssSha512, 5)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, 3)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP384, 5)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa44MlKem512, 2)]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa87MlKem1024, 5)]
    public void NistLevel_ReadsThePostQuantumPart(CertificateKeyAlgorithm algorithm, int level) =>
        Assert.Equal(level, IssuerStrength.NistLevel(algorithm));

    [Theory]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP384)]
    public void NistLevel_ClassicalHasNone(CertificateKeyAlgorithm algorithm) =>
        Assert.Null(IssuerStrength.NistLevel(algorithm));

    [Fact]
    public void EveryAlgorithmIsClassifiedOnPurpose()
    {
        // A new algorithm must decide its level here, not fall through to "classical" by default.
        var classical = new[] { CertificateKeyAlgorithm.Rsa, CertificateKeyAlgorithm.EcdsaP256, CertificateKeyAlgorithm.EcdsaP384 };
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>().Except(classical))
            Assert.NotNull(IssuerStrength.NistLevel(algorithm));
    }

    [Fact]
    public void Enforce_RefusesSubjectAboveIssuer_NamingBothLevels()
    {
        var decision = Evaluate(CertificateKeyAlgorithm.MlDsa87, CertificateKeyAlgorithm.MlDsa65, IssuerStrengthMode.Enforce);

        Assert.False(decision.Allowed);
        var violation = Assert.Single(decision.Violations);
        Assert.Equal(PolicyRules.IssuerStrength, violation.Rule);
        Assert.Contains("level 5", violation.Message);
        Assert.Contains("level 3", violation.Message);
        Assert.Contains("Issuing", violation.Message);
        Assert.Empty(decision.Warnings);
    }

    [Fact]
    public void Warn_AllowsButWarns()
    {
        var decision = Evaluate(CertificateKeyAlgorithm.MlDsa87, CertificateKeyAlgorithm.MlDsa65, IssuerStrengthMode.Warn);

        Assert.True(decision.Allowed);
        Assert.Empty(decision.Violations);
        Assert.Contains("level 5", Assert.Single(decision.Warnings));
    }

    [Fact]
    public void Off_SaysNothing()
    {
        var decision = Evaluate(CertificateKeyAlgorithm.MlDsa87, CertificateKeyAlgorithm.MlDsa44, IssuerStrengthMode.Off);

        Assert.True(decision.Allowed);
        Assert.Empty(decision.Warnings);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.MlDsa65, CertificateKeyAlgorithm.MlDsa65)]
    [InlineData(CertificateKeyAlgorithm.MlDsa44, CertificateKeyAlgorithm.MlDsa87)]
    [InlineData(CertificateKeyAlgorithm.MlKem768, CertificateKeyAlgorithm.MlDsa65)]
    public void EqualOrLowerSubject_IsAllowedWithoutWarning(CertificateKeyAlgorithm subject, CertificateKeyAlgorithm issuer)
    {
        var decision = Evaluate(subject, issuer, IssuerStrengthMode.Enforce);

        Assert.True(decision.Allowed);
        Assert.Empty(decision.Warnings);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.EcdsaP384)]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    public void ClassicalIssuer_IsExempt(CertificateKeyAlgorithm issuer)
    {
        // The P-384 root to ML-DSA-87 migration path must keep working.
        var decision = Evaluate(CertificateKeyAlgorithm.MlDsa87, issuer, IssuerStrengthMode.Enforce);

        Assert.True(decision.Allowed);
        Assert.Empty(decision.Warnings);
    }

    [Fact]
    public void ClassicalSubject_AndUnknownIssuerAlgorithm_AreNotJudged()
    {
        Assert.True(Evaluate(CertificateKeyAlgorithm.Rsa, CertificateKeyAlgorithm.MlDsa44, IssuerStrengthMode.Enforce).Allowed);
        Assert.True(Evaluate(CertificateKeyAlgorithm.MlDsa87, null, IssuerStrengthMode.Enforce).Allowed);
        Assert.True(Evaluate(null, CertificateKeyAlgorithm.MlDsa44, IssuerStrengthMode.Enforce).Allowed);
    }

    [Fact]
    public void OnlyTheIssuingCaIsCompared()
    {
        var request = new CertificateRequest { CommonName = "www.corp.example", Type = "WebServer", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa65 };
        var settings = new CaSettings { PqcStage = PqcStage.Off, IssuerStrengthMode = IssuerStrengthMode.Enforce };

        // The root is weaker than the leaf, but the root vouched for the intermediate, not the leaf.
        var decision = Evaluator.Evaluate(request, Template(), null, null, settings, requester: null,
            issuerPath: [Ca(CertificateKeyAlgorithm.MlDsa65, "Issuing"), Ca(CertificateKeyAlgorithm.MlDsa44, "Root")]);

        Assert.True(decision.Allowed);
    }

    [Fact]
    public void Warn_IsCarriedByAGovernedPolicyDecisionToo()
    {
        var policy = new IssuancePolicy { Name = "P" };
        var version = new IssuancePolicyVersion { PolicyId = policy.Id, VersionNumber = 1, Status = IssuancePolicyVersionStatus.Published };
        var template = Template();
        template.IssuancePolicyId = policy.Id;
        var request = new CertificateRequest { CommonName = "www.corp.example", Type = "WebServer", KeyAlgorithm = CertificateKeyAlgorithm.MlDsa87 };
        var settings = new CaSettings { PqcStage = PqcStage.Off, IssuerStrengthMode = IssuerStrengthMode.Warn };

        var decision = Evaluator.Evaluate(request, template, policy, version, settings, requester: null,
            issuerPath: [Ca(CertificateKeyAlgorithm.MlDsa65)]);

        Assert.True(decision.Allowed);
        Assert.Single(decision.Warnings);
    }
}
