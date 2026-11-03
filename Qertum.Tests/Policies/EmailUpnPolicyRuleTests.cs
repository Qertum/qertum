using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Policies;
using Qertum.Services.Validators;

namespace Qertum.Tests.Policies;

/// <summary>
/// Policies restricted DNS names and IP addresses only, while a template with SAN types email or upn (the seeded
/// ClientAuth) issued whatever the requester typed: a client-authentication certificate carrying another person's UPN
/// signs in as them. Policies now restrict both, and the request's addresses must be local@domain (AI Scan #345 on
/// 1.0.0-rc4.2).
/// </summary>
public sealed class EmailUpnPolicyRuleTests
{
    private readonly IssuancePolicyEvaluator _evaluator = new();
    private static readonly CaSettings Settings = new() { CertificateValidityDays = 365 };

    private static CertificateTemplate Template() => new()
    {
        TypeKey = "ClientAuth",
        IssuancePolicyId = new IssuancePolicyId(Guid.NewGuid()),
        SanTypesJson = """["email","upn"]"""
    };

    private static IssuancePolicyVersion Version(string[]? email = null, string[]? upn = null) => new()
    {
        VersionNumber = 1,
        Status = IssuancePolicyVersionStatus.Published,
        AllowedEmailDomainsJson = JsonSerializer.Serialize(email ?? []),
        AllowedUpnSuffixesJson = JsonSerializer.Serialize(upn ?? [])
    };

    private static CertificateRequest Request(string[]? emails = null, string[]? upns = null) => new()
    {
        CommonName = "Alice",
        Type = "ClientAuth",
        PropertiesJson = JsonSerializer.Serialize(new { emailAddresses = emails ?? [], userPrincipalNames = upns ?? [] })
    };

    private PolicyDecision Evaluate(CertificateRequest request, IssuancePolicyVersion version) =>
        _evaluator.Evaluate(request, Template(), new IssuancePolicy { Name = "people" }, version, Settings);

    [Theory]
    [InlineData("alice@corp.example.com", true)]
    [InlineData("alice@EU.Corp.Example.com", true)]
    [InlineData("alice@corp.example.com.", true)]
    [InlineData("alice@evilcorp.example.com", false)]
    [InlineData("alice@example.com", false)]
    [InlineData("alice@corp.example.com@evil.net", false)]
    [InlineData("alice", false)]
    public void EmailDomain_MatchesOnLabelBoundaries(string email, bool allowed)
    {
        var decision = Evaluate(Request(emails: [email]), Version(email: ["corp.example.com"]));

        Assert.Equal(allowed, decision.Allowed);
        if (!allowed) Assert.Equal(PolicyRules.EmailDomain, Assert.Single(decision.Violations).Rule);
    }

    [Fact]
    public void UpnSuffix_RefusesAnotherDomainsPrincipal_AndCollectsEveryViolation()
    {
        var decision = Evaluate(Request(upns: ["alice@corp.example.com", "administrator@other.example", "bob@x.test"]),
            Version(upn: ["corp.example.com"]));

        Assert.False(decision.Allowed);
        Assert.Equal(["administrator@other.example", "bob@x.test"], decision.Violations.Select(v => v.Value));
        Assert.All(decision.Violations, v => Assert.Equal(PolicyRules.UpnSuffix, v.Rule));
    }

    [Fact]
    public void EmptyLists_LeaveBothUnrestricted_AsBefore()
    {
        Assert.True(Evaluate(Request(emails: ["a@anything.test"], upns: ["b@other.test"]), Version()).Allowed);
    }

    [Fact]
    public void TheEmailRule_DoesNotJudgeUpns_NorTheOtherWayRound()
    {
        Assert.True(Evaluate(Request(upns: ["b@other.test"]), Version(email: ["corp.example.com"])).Allowed);
        Assert.True(Evaluate(Request(emails: ["a@other.test"]), Version(upn: ["corp.example.com"])).Allowed);
    }

    [Theory]
    [InlineData("""{"emailAddresses":["alice@corp.example.com"],"userPrincipalNames":["alice@corp"]}""", true)]
    [InlineData("""{"emailAddresses":["alice"]}""", false)]
    [InlineData("""{"emailAddresses":["@corp.example.com"]}""", false)]
    [InlineData("""{"emailAddresses":["a@b@corp.example.com"]}""", false)]
    [InlineData("""{"emailAddresses":["a b@corp.example.com"]}""", false)]
    [InlineData("""{"userPrincipalNames":["alice@*.corp.example.com"]}""", false)]
    [InlineData("""{"userPrincipalNames":["alice@"]}""", false)]
    public void RequestAddresses_MustBeLocalAtDomain(string propertiesJson, bool valid)
    {
        Assert.Equal(valid, CertificateRequestValidator.ValidatePropertiesJson(propertiesJson, out _));
    }

    [Theory]
    [InlineData("corp.example.com", true)]
    [InlineData("@corp.example.com", false)]
    [InlineData("*.corp.example.com", false)]
    [InlineData("alice@corp.example.com", false)]
    public void DraftRules_AcceptPlainDomainsOnly(string entry, bool valid)
    {
        var validator = new SaveIssuancePolicyDraftRequestValidator();

        Assert.Equal(valid, validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedEmailDomains = [entry] }).IsValid);
        Assert.Equal(valid, validator.Validate(new SaveIssuancePolicyDraftRequest { AllowedUpnSuffixes = [entry] }).IsValid);
    }
}
