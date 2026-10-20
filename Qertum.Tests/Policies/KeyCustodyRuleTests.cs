using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class KeyCustodyRuleTests
{
    private readonly IssuancePolicyEvaluator _evaluator = new();
    private static readonly CaSettings Settings = new() { CertificateValidityDays = 365 };

    private static CertificateTemplate Linked() => new()
    {
        TypeKey = "WebServer",
        IssuancePolicyId = new IssuancePolicyId(Guid.NewGuid())
    };

    private static IssuancePolicy Policy() => new() { Name = "corp" };

    private static IssuancePolicyVersion Version(KeyCustodyMode custody = KeyCustodyMode.Any) => new()
    {
        VersionNumber = 3,
        Status = IssuancePolicyVersionStatus.Published,
        KeyCustody = custody
    };

    private static CertificateRequest Request(string? csrPem = null) => new()
    {
        CommonName = "host.example.com",
        Type = "WebServer",
        PropertiesJson = JsonSerializer.Serialize(new { dnsNames = Array.Empty<string>(), ipAddresses = Array.Empty<string>() }),
        CsrPem = csrPem
    };

    [Fact]
    public void CaGeneratedKey_IsRefused_WhenThePolicyRequiresAClientGeneratedOne()
    {
        var decision = _evaluator.Evaluate(
            Request(), Linked(), Policy(), Version(KeyCustodyMode.RequireClientGenerated), Settings);

        Assert.False(decision.Allowed);
        var violation = Assert.Single(decision.Violations);
        Assert.Equal(PolicyRules.KeyCustody, violation.Rule);
        Assert.Equal("ca-generated", violation.Value);
        Assert.Equal(
            "Policy 'corp' requires a client-generated key: the request must carry a CSR, so enrollment " +
            "has to go through ACME or EST.",
            violation.Message);
    }

    [Fact]
    public void CsrCarryingRequest_IsAdmitted_WhenThePolicyRequiresAClientGeneratedKey() =>
        Assert.True(_evaluator.Evaluate(
            Request("-----BEGIN CERTIFICATE REQUEST-----\nMII\n-----END CERTIFICATE REQUEST-----"),
            Linked(), Policy(), Version(KeyCustodyMode.RequireClientGenerated), Settings).Allowed);

    [Fact]
    public void BlankCsr_CountsAsCaGenerated()
    {
        // The consumer writes an empty PrivateKeyPem for CSR-issued requests; the reverse — a blank
        // CsrPem — must not read as proof the client held the key.
        var decision = _evaluator.Evaluate(
            Request("   "), Linked(), Policy(), Version(KeyCustodyMode.RequireClientGenerated), Settings);

        Assert.False(decision.Allowed);
        Assert.Equal(PolicyRules.KeyCustody, Assert.Single(decision.Violations).Rule);
    }

    [Fact]
    public void AnyCustody_AdmitsACaGeneratedKey() =>
        Assert.True(_evaluator.Evaluate(Request(), Linked(), Policy(), Version(), Settings).Allowed);

    [Fact]
    public void DefaultCustody_IsAny() =>
        Assert.Equal(KeyCustodyMode.Any, new IssuancePolicyVersion().KeyCustody);

    [Fact]
    public void UnlinkedTemplate_HasNoCustodyRuleToApply() =>
        Assert.True(_evaluator.Evaluate(Request(), new CertificateTemplate { TypeKey = "WebServer" },
            null, null, Settings).Allowed);

    [Fact]
    public void RootCaRequest_IsNotSubjectToTheRule()
    {
        var request = Request();
        request.Type = WellKnownCertificateTypes.RootCa;

        Assert.True(_evaluator.Evaluate(
            request, Linked(), Policy(), Version(KeyCustodyMode.RequireClientGenerated), Settings).Allowed);
    }

    [Fact]
    public void AdmitsCaGeneratedKey_IsTheSameTestTheEvaluatorUses()
    {
        Assert.True(KeyCustodyRule.AdmitsCaGeneratedKey(Version()));
        Assert.False(KeyCustodyRule.AdmitsCaGeneratedKey(Version(KeyCustodyMode.RequireClientGenerated)));
    }
}
