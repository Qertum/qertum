using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class CaPermissionRuleTests
{
    private static readonly IssuancePolicyEvaluator Evaluator = new();
    private static readonly CaSettings Settings = new() { Id = 1 };

    // Copy the construction of a CertificateTemplate from IssuancePolicyEvaluatorTests if more members are required.
    private static CertificateTemplate Template(string typeKey, string usages) =>
        new() { TypeKey = typeKey, KeyUsagesJson = usages };

    private static readonly CertificateTemplate Leaf = Template("WebServer", "[\"DigitalSignature\"]");
    private static readonly CertificateTemplate Ca = Template("SubordinateCA", "[\"KeyCertSign\",\"CrlSign\"]");

    private static PolicyDecision Run(CertificateTemplate template, CallerContext? caller) =>
        Evaluator.Evaluate(new CertificateRequest { CommonName = "x", Type = template.TypeKey, RequestedBy = "u" },
            template, policy: null, publishedVersion: null, Settings, caller: caller);

    private static CallerContext Human(bool admin = false, bool ca = false) =>
        new("sub-1", "alice", admin, ca);

    [Fact]
    public void ANullCaller_SkipsTheRule() => Assert.True(Run(Ca, null).Allowed);

    [Fact]
    public void ALeafTemplate_NeverNeedsThePermission() => Assert.True(Run(Leaf, Human()).Allowed);

    [Fact]
    public void ACaTemplate_WithoutThePermission_IsRefused_NamingTheRuleAndPermission()
    {
        var decision = Run(Ca, Human());

        Assert.False(decision.Allowed);
        var violation = Assert.Single(decision.Violations);
        Assert.Equal(PolicyRules.CaPermission, violation.Rule);
        Assert.Contains("certificates.ca", violation.Message);
        Assert.Contains("SubordinateCA", violation.Message);
    }

    [Fact]
    public void ACaTemplate_WithThePermission_IsAdmitted() => Assert.True(Run(Ca, Human(ca: true)).Allowed);

    [Fact]
    public void Admin_BypassesThePermission() => Assert.True(Run(Ca, Human(admin: true)).Allowed);

    [Fact]
    public void TheProtocolCaller_IsNeverAdmittedForACaTemplate()
    {
        var decision = Run(Ca, CallerContext.Protocol);

        Assert.False(decision.Allowed);
        Assert.Equal(PolicyRules.CaPermission, Assert.Single(decision.Violations).Rule);
        Assert.Contains("ACME", decision.Violations[0].Message);
        Assert.True(Run(Leaf, CallerContext.Protocol).Allowed);
    }

    [Fact]
    public void TheRuleAlsoAppliesUnderAGovernedTemplate()
    {
        // A linked template takes the second branch of the evaluator; the rule must run there too.
        var policy = new IssuancePolicy { Name = "p" };
        var version = new IssuancePolicyVersion
        {
            PolicyId = policy.Id, VersionNumber = 1, Status = IssuancePolicyVersionStatus.Published
        };
        var governed = Template("SubordinateCA", "[\"KeyCertSign\"]");
        governed.IssuancePolicyId = policy.Id;

        var decision = Evaluator.Evaluate(
            new CertificateRequest { CommonName = "x", Type = "SubordinateCA", RequestedBy = "u" },
            governed, policy, version, Settings, caller: Human());

        Assert.Contains(decision.Violations, v => v.Rule == PolicyRules.CaPermission);
    }

    [Theory]
    [InlineData("sub-1", "alice", "sub-1", "alice", true)]
    [InlineData("sub-1", "alice", "sub-2", "alice", false)] // same display name, different subject: not the requester
    [InlineData(null, "alice", "sub-9", "alice", true)]      // legacy row: no subject, names compare
    [InlineData(null, "alice", "sub-9", "bob", false)]
    public void SelfApproval_ComparesSubjects_FallingBackToNamesOnlyForLegacyRows(
        string? ownerSubject, string ownerName, string approverSubject, string approverName, bool expected)
    {
        var request = new CertificateRequest { RequestedBySubject = ownerSubject, RequestedBy = ownerName };
        var approver = new CallerContext(approverSubject, approverName, IsAdmin: false, HoldsCaPermission: true);

        Assert.Equal(expected, IndependentApprovalRule.IsSelfApproval(request, approver));
    }
}
