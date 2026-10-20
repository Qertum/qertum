using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class CertificateRequestPreviewServiceTests
{
    private const string Actor = "alice";

    private static CertificateRequest WebServer(string cn) =>
        new() { CommonName = cn, RequestedBy = Actor, Type = "WebServer" };

    [Fact]
    public async Task UnlinkedTemplate_IsAllowedAndReportsTheTemplateDefault()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(WebServer("host.anywhere"), ct);

        Assert.True(preview.Allowed);
        Assert.Empty(preview.Violations);
        Assert.True(preview.TemplateExists);
        Assert.Equal("WebServer", preview.TemplateTypeKey);
        Assert.Null(preview.PolicyName);
        Assert.Equal("RSA", preview.EffectiveKeyAlgorithm);
        Assert.True(preview.EffectiveValidityDays > 0);
    }

    [Fact]
    public async Task GovernedRequest_ReportsThePolicyThatWouldApply()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var version = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer",
            // The ceiling must clear the template's own default (365) or every request under this
            // policy is refused — the invariant publish and template-link already enforce.
            dnsSuffixes: ["corp.example.com"], name: "corp-web", maxValidityDays: 730, ct: ct);

        var preview = await scope.CreatePreviewService()
            .PreviewCreateAsync(WebServer("host.corp.example.com"), ct);

        Assert.True(preview.Allowed);
        Assert.Equal("corp-web", preview.PolicyName);
        Assert.Equal(1, preview.PolicyVersionNumber);
        Assert.Equal(version.Id, preview.PolicyVersionId);
    }

    [Fact]
    public async Task UnknownType_IsRejectedWithTheTemplateRule()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var candidate = new CertificateRequest { CommonName = "a.example.com", RequestedBy = Actor, Type = "NoSuchType" };
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);

        Assert.False(preview.Allowed);
        Assert.False(preview.TemplateExists);
        Assert.Equal(0, preview.EffectiveValidityDays);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.Template);
    }

    [Fact]
    public async Task DuplicateActiveCommonName_IsReportedAsAViolation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await scope.CreateRequestService().CreateAsync(WebServer("taken.example.com"), Actor, ct);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(WebServer("taken.example.com"), ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.DuplicateCommonName);
    }

    [Fact]
    public async Task Renewal_DoesNotReportADuplicate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var original = await scope.CreateRequestService().CreateAsync(WebServer("renew.example.com"), Actor, ct);

        var candidate = new CertificateRequest
        {
            CommonName = "renew.example.com",
            RequestedBy = Actor,
            Type = "WebServer",
            RenewedFromId = original.Id
        };
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);

        Assert.True(preview.Allowed);
    }

    [Fact]
    public async Task Preview_AtEnforce_ReportsPqcOnlyViolation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await SetStageAsync(scope, PqcStage.Enforce, ct);

        var candidate = WebServer("host.example.com");
        candidate.KeyAlgorithm = CertificateKeyAlgorithm.Rsa;
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.PqcOnly);
    }

    [Fact]
    public async Task Preview_AtWarn_IsAllowedWithWarnings()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await SetStageAsync(scope, PqcStage.Warn, ct);

        var candidate = WebServer("host.example.com");
        candidate.KeyAlgorithm = CertificateKeyAlgorithm.Rsa;
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);

        Assert.True(preview.Allowed);
        Assert.Single(preview.Warnings);
    }

    [Fact]
    public async Task Preview_WithNoSettingsRow_TreatsTheCaAsEnforce_AndDoesNotInsertOne()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct, seedSettings: false);

        var candidate = WebServer("host.example.com");
        candidate.KeyAlgorithm = CertificateKeyAlgorithm.Rsa;
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.PqcOnly);
        Assert.False(await scope.Db.Settings.AnyAsync(ct));
    }

    private static async Task SetStageAsync(PolicyTestDb scope, PqcStage stage, CancellationToken ct)
    {
        var settings = await scope.Db.Settings.SingleAsync(s => s.Id == 1, ct);
        settings.PqcStage = stage;
        await scope.Db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task TwoBrokenRules_AreBothReported()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer",
            dnsSuffixes: ["corp.example.com"], algorithms: ["ECDSA-P256"], ct: ct);

        var candidate = WebServer("host.other.net");
        candidate.KeyAlgorithm = CertificateKeyAlgorithm.Rsa;
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);

        Assert.False(preview.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.DnsSuffix);
        Assert.Contains(preview.Violations, v => v.Rule == PolicyRules.KeyAlgorithm);
    }

    [Fact]
    public async Task RequestedValidity_IsReportedWhenItFitsTheCeiling()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", maxValidityDays: 90, ct: ct);

        var candidate = WebServer("host.example.com");
        candidate.ValidityDays = 30;
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);

        Assert.True(preview.Allowed);
        Assert.Equal(30, preview.EffectiveValidityDays);
    }

    [Fact]
    public async Task Preview_WritesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        await scope.CreatePreviewService().PreviewCreateAsync(WebServer("host.example.com"), ct);

        Assert.Equal(0, await scope.Db.CertificateRequests.CountAsync(ct));
        Assert.Empty(scope.Audit.Entries);
    }

    // The test that keeps preview honest: whatever preview says, the real create must agree.
    [Theory]
    [InlineData("host.corp.example.com", null, true)]
    [InlineData("host.other.net", null, false)]
    [InlineData("host.corp.example.com", 3650, false)]
    public async Task PreviewVerdict_MatchesTheRealCreate(string commonName, int? validityDays, bool expectedAllowed)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer",
            dnsSuffixes: ["corp.example.com"], maxValidityDays: 730, ct: ct);

        var candidate = WebServer(commonName);
        candidate.ValidityDays = validityDays;
        var preview = await scope.CreatePreviewService().PreviewCreateAsync(candidate, ct);
        Assert.Equal(expectedAllowed, preview.Allowed);

        var real = WebServer(commonName);
        real.ValidityDays = validityDays;
        var created = await Record.ExceptionAsync(() => scope.CreateRequestService().CreateAsync(real, Actor, ct));

        Assert.Equal(expectedAllowed, created is null);
    }

    [Fact]
    public async Task PreviewVerdict_MatchesTheRealCreate_ForADuplicate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        await scope.CreateRequestService().CreateAsync(WebServer("taken.example.com"), Actor, ct);

        var preview = await scope.CreatePreviewService().PreviewCreateAsync(WebServer("taken.example.com"), ct);
        Assert.False(preview.Allowed);

        await Assert.ThrowsAsync<DuplicateRequestException>(
            () => scope.CreateRequestService().CreateAsync(WebServer("taken.example.com"), Actor, ct));
    }
}
