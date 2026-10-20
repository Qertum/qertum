using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class IssuerPathRuleTests
{
    private static readonly IssuancePolicyEvaluator Evaluator = new();

    private static Issuer Ca(string name, int? pathLength = null, string[]? permittedDns = null, string[]? excludedDns = null,
        string[]? permittedIp = null, string[]? excludedIp = null) => new()
    {
        Name = name,
        PathLengthConstraint = pathLength,
        PermittedDnsSuffixesJson = JsonSerializer.Serialize(permittedDns ?? []),
        ExcludedDnsSuffixesJson = JsonSerializer.Serialize(excludedDns ?? []),
        PermittedIpRangesJson = JsonSerializer.Serialize(permittedIp ?? []),
        ExcludedIpRangesJson = JsonSerializer.Serialize(excludedIp ?? [])
    };

    private static CertificateTemplate Template(bool ca = false) => new()
    {
        TypeKey = ca ? "SubordinateCA" : "WebServer",
        KeyUsagesJson = ca ? "[\"KeyCertSign\"]" : "[\"DigitalSignature\"]",
        SanTypesJson = "[\"dns\",\"ip\"]"
    };

    private static CertificateRequest Request(string cn, string[]? dns = null, string[]? ips = null) => new()
    {
        CommonName = cn,
        Type = "WebServer",
        PropertiesJson = JsonSerializer.Serialize(new { dnsNames = dns ?? [], ipAddresses = ips ?? [] })
    };

    private static PolicyDecision Evaluate(CertificateRequest request, CertificateTemplate template, params Issuer[] path) =>
        Evaluator.Evaluate(request, template, null, null, new CaSettings { PqcStage = PqcStage.Off }, requester: null, issuerPath: path);

    [Fact]
    public void NameInsidePermitted_IsAllowed() =>
        Assert.True(Evaluate(Request("www.corp.example", ["api.corp.example"]), Template(), Ca("I", permittedDns: ["corp.example"])).Allowed);

    [Fact]
    public void NameOutsidePermitted_IsRefused_NamingIt()
    {
        var decision = Evaluate(Request("www.corp.example", ["www.evilcorp.example"]), Template(), Ca("Issuing", permittedDns: ["corp.example"]));

        var violation = Assert.Single(decision.Violations);
        Assert.Equal(PolicyRules.IssuerNameConstraints, violation.Rule);
        Assert.Equal("www.evilcorp.example", violation.Value);
        Assert.Contains("Issuing", violation.Message);
    }

    [Fact]
    public void ExcludedWinsInsidePermitted() =>
        Assert.False(Evaluate(Request("db.secret.corp.example"), Template(),
            Ca("I", permittedDns: ["corp.example"], excludedDns: ["secret.corp.example"])).Allowed);

    [Fact]
    public void EveryCaOnThePathApplies()
    {
        var issuing = Ca("Issuing", permittedDns: ["corp.example", "other.example"]);
        var root = Ca("Root", permittedDns: ["corp.example"]);

        Assert.False(Evaluate(Request("www.other.example"), Template(), issuing, root).Allowed);
    }

    [Fact]
    public void WildcardIsJudgedByItsBaseName() =>
        Assert.True(Evaluate(Request("*.corp.example"), Template(), Ca("I", permittedDns: ["corp.example"])).Allowed);

    [Fact]
    public void NonHostCommonName_IsNotADnsName() =>
        Assert.True(Evaluate(Request("Jane Doe"), Template(), Ca("I", permittedDns: ["corp.example"])).Allowed);

    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("11.0.0.1", false)]
    [InlineData("10.9.0.1", false)]
    [InlineData("2001:db8::1", false)]
    public void IpAddresses_AreCheckedAgainstPermittedAndExcluded(string ip, bool allowed) =>
        Assert.Equal(allowed, Evaluate(Request("h.corp.example", ips: [ip]), Template(),
            Ca("I", permittedIp: ["10.0.0.0/8"], excludedIp: ["10.9.0.0/16"])).Allowed);

    [Fact]
    public void DnsOnlyConstraints_LeaveIpsUnconstrained() =>
        Assert.True(Evaluate(Request("h.corp.example", ips: ["192.0.2.1"]), Template(), Ca("I", permittedDns: ["corp.example"])).Allowed);

    [Fact]
    public void CaCertificateUnderPathLengthZero_IsRefused()
    {
        var decision = Evaluate(Request("Sub CA"), Template(ca: true), Ca("Issuing", pathLength: 0));

        Assert.Equal(PolicyRules.IssuerPathLength, Assert.Single(decision.Violations).Rule);
    }

    [Fact]
    public void CaCertificate_CountsDepthAgainstAncestors()
    {
        // Root pathLen 1 already has "Issuing" below it; another CA under Issuing would make two.
        Assert.False(Evaluate(Request("Sub CA"), Template(ca: true), Ca("Issuing"), Ca("Root", pathLength: 1)).Allowed);
        Assert.True(Evaluate(Request("Sub CA"), Template(ca: true), Ca("Issuing"), Ca("Root", pathLength: 2)).Allowed);
    }

    [Fact]
    public void LeafUnderPathLengthZero_IsFine() =>
        Assert.True(Evaluate(Request("h.corp.example"), Template(), Ca("I", pathLength: 0)).Allowed);

    [Fact]
    public void UngovernedTemplate_IsStillChecked()
    {
        var template = Template();
        template.IssuancePolicyId = null;

        Assert.False(Evaluate(Request("www.evil.example"), template, Ca("I", permittedDns: ["corp.example"])).Allowed);
    }

    [Fact]
    public void NoPath_ChecksNothing() =>
        Assert.True(Evaluator.Evaluate(Request("www.evil.example"), Template(), null, null, new CaSettings { PqcStage = PqcStage.Off }).Allowed);
}
