using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class IssuancePolicyServiceTests
{
    private static IssuancePolicyService CreateService(PolicyTestDb scope) =>
        new(scope.Db, new IssuancePolicyEvaluator());

    [Fact]
    public async Task SeededTemplate_WithoutPolicy_IsUnrestricted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var decision = await CreateService(scope).EvaluateAsync(
            new CertificateRequest { CommonName = "any.where", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off }, ct);

        Assert.True(decision.Allowed);
        Assert.Null(decision.PolicyVersionId);
    }

    [Fact]
    public async Task LinkedTemplate_LoadsPublishedVersion_AndRejectsOutsideSuffix()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var version = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer",
            dnsSuffixes: ["corp.example.com"], name: "corp", ct: ct);

        var service = CreateService(scope);
        var allowed = await service.EvaluateAsync(
            new CertificateRequest { CommonName = "a.corp.example.com", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off }, ct);
        var rejected = await service.EvaluateAsync(
            new CertificateRequest { CommonName = "a.other.net", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off }, ct);

        Assert.True(allowed.Allowed);
        Assert.Equal(version.Id, allowed.PolicyVersionId);
        Assert.False(rejected.Allowed);
        Assert.Equal("corp", rejected.PolicyName);
    }

    [Fact]
    public async Task UnknownType_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var decision = await CreateService(scope).EvaluateAsync(
            new CertificateRequest { CommonName = "x", Type = "NoSuchTemplate" }, new CaSettings { PqcStage = PqcStage.Off }, ct);

        Assert.False(decision.Allowed);
        Assert.Equal(PolicyRules.Template, Assert.Single(decision.Violations).Rule);
    }

    [Fact]
    public void ViolationException_CarriesDecisionStageAndSummary()
    {
        var decision = new PolicyDecision(false, Guid.NewGuid(), "corp", 2,
            [new IssuancePolicyViolation(PolicyRules.DnsSuffix, "x.net", "'x.net' is not allowed.")]);

        var ex = new IssuancePolicyViolationException(decision, PolicyEnforcementStage.Approval);

        Assert.Same(decision, ex.Decision);
        Assert.Equal(PolicyEnforcementStage.Approval, ex.Stage);
        Assert.Equal(decision.Summarize(), ex.Message);
    }
}
