using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class RequesterRoleRuleTests
{
    private readonly IssuancePolicyEvaluator _evaluator = new();
    private static readonly CaSettings Settings = new() { CertificateValidityDays = 365 };

    private static CertificateTemplate Linked() => new()
    {
        TypeKey = "WebServer",
        IssuancePolicyId = new IssuancePolicyId(Guid.NewGuid())
    };

    private static IssuancePolicy Policy() => new() { Name = "corp" };

    private static IssuancePolicyVersion Version(params string[] roles) => new()
    {
        VersionNumber = 3,
        Status = IssuancePolicyVersionStatus.Published,
        AllowedRequesterRolesJson = JsonSerializer.Serialize(roles)
    };

    private static CertificateRequest Request() => new()
    {
        CommonName = "host.example.com",
        Type = "WebServer",
        PropertiesJson = JsonSerializer.Serialize(new { dnsNames = Array.Empty<string>(), ipAddresses = Array.Empty<string>() })
    };

    private PolicyDecision Evaluate(IssuancePolicyVersion version, RequesterRoles? requester) =>
        _evaluator.Evaluate(Request(), Linked(), Policy(), version, Settings, requester);

    [Fact]
    public void ListedRole_IsAdmitted_AndNamed()
    {
        var decision = Evaluate(Version("ops", "pki"), RequesterRoles.From(["viewer", "pki"]));

        Assert.True(decision.Allowed);
        Assert.Equal("pki", decision.MatchedRequesterRole);
        Assert.True(decision.RequesterRolesListed);
    }

    [Fact]
    public void UnlistedRole_IsRefused_WithTheAllowedRoles()
    {
        var decision = Evaluate(Version("ops", "pki"), RequesterRoles.From(["viewer"]));

        Assert.False(decision.Allowed);
        var violation = Assert.Single(decision.Violations);
        Assert.Equal(PolicyRules.RequesterRole, violation.Rule);
        Assert.Equal("viewer", violation.Value);
        Assert.Equal("Role(s) 'viewer' may not request under policy 'corp'; allowed: ops, pki.", violation.Message);
    }

    [Fact]
    public void NoRoles_IsRefusedWithNone()
    {
        var violation = Assert.Single(Evaluate(Version("ops"), RequesterRoles.From([])).Violations);

        Assert.Equal("(none)", violation.Value);
    }

    [Fact]
    public void RoleMatch_IgnoresCase() =>
        Assert.True(Evaluate(Version("ops"), RequesterRoles.From(["OPS"])).Allowed);

    [Fact]
    public void Admin_Bypasses()
    {
        var decision = Evaluate(Version("ops"), RequesterRoles.From(["Admin"]));

        Assert.True(decision.Allowed);
        Assert.True(decision.RequesterIsAdmin);
        Assert.Null(decision.MatchedRequesterRole);
    }

    [Fact]
    public void EmptyList_IsUnrestricted()
    {
        var decision = Evaluate(Version(), RequesterRoles.From(["viewer"]));

        Assert.True(decision.Allowed);
        Assert.False(decision.RequesterRolesListed);
        Assert.Null(decision.MatchedRequesterRole);
    }

    [Fact]
    public void NullRequester_SkipsTheRule_ButReportsItIsListed()
    {
        var decision = Evaluate(Version("ops"), requester: null);

        Assert.True(decision.Allowed);
        Assert.True(decision.RequesterRolesListed);
    }

    [Fact]
    public void UnlinkedTemplate_IgnoresRequester() =>
        Assert.True(_evaluator.Evaluate(Request(), new CertificateTemplate { TypeKey = "WebServer" },
            null, null, Settings, RequesterRoles.From([])).Allowed);

    [Fact]
    public void Admits_IsTheSameTestTheEvaluatorUses()
    {
        Assert.True(RequesterRoleRule.Admits(Version("ops"), RequesterRoles.From(["ops"]), out var matched));
        Assert.Equal("ops", matched);
        Assert.False(RequesterRoleRule.Admits(Version("ops"), RequesterRoles.From(["x"]), out _));
        Assert.True(RequesterRoleRule.Admits(Version(), RequesterRoles.From([]), out _));
    }
}
