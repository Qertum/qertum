using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class IssuancePolicyEvaluatorTests
{
    private readonly IssuancePolicyEvaluator _evaluator = new();
    private static readonly CaSettings Settings = new() { CertificateValidityDays = 365 };

    private static CertificateTemplate Template(int? validityDays = null) => new()
    {
        TypeKey = "WebServer",
        IssuancePolicyId = new IssuancePolicyId(Guid.NewGuid()),
        ValidityDays = validityDays
    };

    private static IssuancePolicy Policy() => new() { Name = "corp" };

    private static IssuancePolicyVersion Version(
        string[]? dns = null, string[]? ip = null, string[]? algs = null, int? maxDays = null) => new()
    {
        VersionNumber = 3,
        Status = IssuancePolicyVersionStatus.Published,
        AllowedDnsSuffixesJson = JsonSerializer.Serialize(dns ?? []),
        AllowedIpRangesJson = JsonSerializer.Serialize(ip ?? []),
        AllowedKeyAlgorithmsJson = JsonSerializer.Serialize(algs ?? []),
        MaxValidityDays = maxDays
    };

    private static CertificateRequest Request(
        string cn, string[]? dnsNames = null, string[]? ips = null, CertificateKeyAlgorithm? alg = null,
        int? validityDays = null) => new()
    {
        CommonName = cn,
        Type = "WebServer",
        PropertiesJson = JsonSerializer.Serialize(new { dnsNames = dnsNames ?? [], ipAddresses = ips ?? [] }),
        KeyAlgorithm = alg,
        ValidityDays = validityDays
    };

    [Theory]
    // No policy ceiling: a request may shorten its validity, never lengthen it past the default
    // it would otherwise get.
    [InlineData(90, null, true)]
    [InlineData(365, null, true)]
    [InlineData(366, null, false)]
    // With a ceiling, the ceiling decides — under it is fine even above the template default.
    [InlineData(200, 180, false)]
    [InlineData(120, 180, true)]
    [InlineData(null, 180, false)] // the 365-day template default already exceeds the maximum
    public void Validity_ShortensFreelyButNeverExceedsTheDefaultOrTheCeiling(int? requested, int? maxDays, bool allowed)
    {
        var decision = _evaluator.Evaluate(
            Request("host.example.com", validityDays: requested), Template(), Policy(), Version(maxDays: maxDays), Settings);

        Assert.Equal(allowed, decision.Allowed);
    }

    [Theory]
    [InlineData("corp.example.com", true)]
    [InlineData("a.corp.example.com", true)]
    [InlineData("A.Corp.Example.COM", true)]
    [InlineData("a.corp.example.com.", true)]
    [InlineData("*.corp.example.com", true)]
    [InlineData("evilcorp.example.com", false)]
    [InlineData("example.com", false)]
    [InlineData("*.example.com", false)]
    [InlineData("corp.example.com.evil.net", false)]
    public void DnsSuffix_MatchesOnLabelBoundaries(string commonName, bool allowed)
    {
        var decision = _evaluator.Evaluate(Request(commonName), Template(), Policy(), Version(dns: ["corp.example.com"]), Settings);

        Assert.Equal(allowed, decision.Allowed);
    }

    [Fact]
    public void DnsSuffix_InternationalizedNameComparedAsPunycode()
    {
        var decision = _evaluator.Evaluate(Request("host.bücher.example"), Template(), Policy(),
            Version(dns: ["xn--bcher-kva.example"]), Settings);

        Assert.True(decision.Allowed);
    }

    [Fact]
    public void DnsSuffix_EverySanIsChecked_AndEveryViolationCollected()
    {
        var decision = _evaluator.Evaluate(
            Request("ok.corp.example.com", dnsNames: ["bad1.other.net", "ok2.corp.example.com", "bad2.other.net"]),
            Template(), Policy(), Version(dns: ["corp.example.com"]), Settings);

        Assert.False(decision.Allowed);
        Assert.Equal(["bad1.other.net", "bad2.other.net"], decision.Violations.Select(v => v.Value));
        Assert.All(decision.Violations, v => Assert.Equal(PolicyRules.DnsSuffix, v.Rule));
    }

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("10.2.0.1", false)]
    [InlineData("fd00::5", true)]
    [InlineData("not-an-ip", false)]
    public void IpRange_EveryAddressMustFallInsideARange(string ip, bool allowed)
    {
        var decision = _evaluator.Evaluate(Request("host", ips: [ip]), Template(), Policy(),
            Version(ip: ["10.1.0.0/16", "fd00::/8"]), Settings);

        Assert.Equal(allowed, decision.Allowed);
    }

    [Theory]
    [InlineData(null, false)] // effective RSA
    [InlineData(CertificateKeyAlgorithm.EcdsaP256, true)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, true)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP384, false)]
    public void KeyAlgorithm_MatchesCanonicalName(CertificateKeyAlgorithm? algorithm, bool allowed)
    {
        var decision = _evaluator.Evaluate(Request("host", alg: algorithm), Template(), Policy(),
            Version(algs: ["ECDSA-P256", "HYBRID-ECDSA-P256"]), Settings);

        Assert.Equal(allowed, decision.Allowed);
    }

    [Theory]
    [InlineData(null, 400, true)]   // global 365 <= 400
    [InlineData(null, 300, false)]  // global 365 > 300
    [InlineData(90, 100, true)]     // template 90 <= 100
    [InlineData(3650, 825, false)]  // template 3650 > 825
    public void MaxValidity_AppliesToEffectiveDefault(int? templateDays, int max, bool allowed)
    {
        var decision = _evaluator.Evaluate(Request("host"), Template(templateDays), Policy(), Version(maxDays: max), Settings);

        Assert.Equal(allowed, decision.Allowed);
    }

    [Fact]
    public void EmptyRules_AreUnrestricted_ButRecordTheVersion()
    {
        var version = Version();
        var decision = _evaluator.Evaluate(
            Request("anything.anywhere", ips: ["8.8.8.8"], alg: CertificateKeyAlgorithm.Rsa),
            Template(), Policy(), version, Settings);

        Assert.True(decision.Allowed);
        Assert.Equal(version.Id, decision.PolicyVersionId);
        Assert.Equal(3, decision.VersionNumber);
    }

    [Fact]
    public void UnlinkedTemplate_IsUnrestricted()
    {
        var template = new CertificateTemplate { TypeKey = "WebServer" };

        var decision = _evaluator.Evaluate(Request("x"), template, null, null, Settings);

        Assert.Same(PolicyDecision.Unrestricted, decision);
    }

    [Fact]
    public void RootCa_BypassesEvenWithoutTemplate()
    {
        var request = Request("Root");
        request.Type = WellKnownCertificateTypes.RootCa;

        Assert.True(_evaluator.Evaluate(request, null, null, null, Settings).Allowed);
    }

    [Fact]
    public void MissingTemplate_IsRejected()
    {
        var decision = _evaluator.Evaluate(Request("x"), null, null, null, Settings);

        Assert.False(decision.Allowed);
        Assert.Equal(PolicyRules.Template, Assert.Single(decision.Violations).Rule);
    }

    [Fact]
    public void LinkedTemplateWithoutPublishedVersion_IsRejected()
    {
        var decision = _evaluator.Evaluate(Request("x"), Template(), Policy(), null, Settings);

        Assert.False(decision.Allowed);
        Assert.Equal(PolicyRules.Template, Assert.Single(decision.Violations).Rule);
    }

    [Fact]
    public void Summarize_NamesPolicyVersionAndEveryMessage()
    {
        var decision = _evaluator.Evaluate(Request("a.other.net", dnsNames: ["b.other.net"]), Template(), Policy(),
            Version(dns: ["corp.example.com"]), Settings);

        var summary = decision.Summarize();

        Assert.StartsWith("Issuance policy 'corp' v3 violation: ", summary);
        Assert.Contains("a.other.net", summary);
        Assert.Contains("b.other.net", summary);
    }
}
