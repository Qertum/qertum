using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class IssuancePolicyManagementServiceTests
{
    private const string Author = "author";
    private const string Publisher = "publisher";

    private static async Task<IssuancePolicyResponse> CreateWithRulesAsync(
        IssuancePolicyManagementService service, string name, CancellationToken ct,
        string[]? dns = null, int? maxDays = null)
    {
        var created = await service.CreateAsync(new SaveIssuancePolicyRequest { Name = name }, Author, ct);
        return (await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest
        {
            AllowedDnsSuffixes = [.. dns ?? []],
            MaxValidityDays = maxDays
        }, Author, ct))!;
    }

    private static async Task<IssuancePolicyResponse> PublishCurrentDraftAsync(
        IssuancePolicyManagementService service, IssuancePolicyId id, CancellationToken ct)
    {
        var draft = (await service.GetAsync(id, ct))!.Draft!;
        return (await service.PublishAsync(id, new PublishIssuancePolicyRequest
        {
            DraftVersionId = draft.Id,
            DraftUpdatedAtUtc = draft.UpdatedAtUtc
        }, Publisher, ct))!;
    }

    private static async Task LinkAsync(PolicyTestDb scope, string typeKey, IssuancePolicyId? id, CancellationToken ct)
    {
        var template = await scope.Db.CertificateTemplates.SingleAsync(t => t.TypeKey == typeKey, ct);
        template.IssuancePolicyId = id;
        await scope.Db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task Create_OpensEmptyDraftV1_WithNothingPublished()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);

        var created = await scope.CreateManagementService().CreateAsync(
            new SaveIssuancePolicyRequest { Name = "corp", Description = "internal" }, Author, ct);

        Assert.Null(created.Published);
        Assert.NotNull(created.Draft);
        Assert.Equal(1, created.Draft.VersionNumber);
        Assert.Empty(created.Draft.AllowedDnsSuffixes);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "IssuancePolicyCreated" && e.ResourceName == "corp");
    }

    [Fact]
    public async Task Create_DuplicateName_Conflicts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        await service.CreateAsync(new SaveIssuancePolicyRequest { Name = "corp" }, Author, ct);

        await Assert.ThrowsAsync<IssuancePolicyConflictException>(
            () => service.CreateAsync(new SaveIssuancePolicyRequest { Name = "corp" }, Author, ct));
    }

    [Fact]
    public async Task SaveDraft_NormalizesAndDeduplicatesRules()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await service.CreateAsync(new SaveIssuancePolicyRequest { Name = "corp" }, Author, ct);

        var saved = await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest
        {
            AllowedDnsSuffixes = ["Corp.Example.COM.", "corp.example.com"],
            AllowedIpRanges = [" 10.0.0.0/8 "],
            AllowedKeyAlgorithms = ["ecdsa-p256", "ECDSA-P256"],
            MaxValidityDays = 397
        }, Author, ct);

        Assert.Equal(["corp.example.com"], saved!.Draft!.AllowedDnsSuffixes);
        Assert.Equal(["10.0.0.0/8"], saved.Draft.AllowedIpRanges);
        Assert.Equal(["ECDSA-P256"], saved.Draft.AllowedKeyAlgorithms);
        Assert.Equal(397, saved.Draft.MaxValidityDays);
    }

    [Fact]
    public async Task Publish_PromotesDraft_AndSupersedesPreviousVersion()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "corp", ct, dns: ["corp.example.com"]);
        await PublishCurrentDraftAsync(service, created.Id, ct);

        await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest { AllowedDnsSuffixes = ["other.com"] }, Author, ct);
        var published = await PublishCurrentDraftAsync(service, created.Id, ct);

        Assert.Equal(2, published.Published!.VersionNumber);
        Assert.Equal(["other.com"], published.Published.AllowedDnsSuffixes);
        Assert.Equal(Publisher, published.Published.PublishedBy);
        Assert.Null(published.Draft);
        var versions = await service.GetVersionsAsync(created.Id, ct);
        Assert.Equal([IssuancePolicyVersionStatus.Published, IssuancePolicyVersionStatus.Superseded],
            versions!.Select(v => v.Status));
        Assert.Contains(scope.Audit.Entries, e => e.Action == "IssuancePolicyPublished" && e.PerformedBy == Publisher);
    }

    [Fact]
    public async Task Publish_DraftChangedAfterReview_Conflicts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "corp", ct, dns: ["corp.example.com"]);
        var reviewed = (await service.GetAsync(created.Id, ct))!.Draft!;

        // Someone edits the draft after the publisher read it.
        var draftRow = await scope.Db.IssuancePolicyVersions.SingleAsync(v => v.Id == reviewed.Id, ct);
        draftRow.AllowedDnsSuffixesJson = """["com"]""";
        draftRow.UpdatedAtUtc = reviewed.UpdatedAtUtc.AddSeconds(1);
        await scope.Db.SaveChangesAsync(ct);

        await Assert.ThrowsAsync<IssuancePolicyConflictException>(() => service.PublishAsync(created.Id,
            new PublishIssuancePolicyRequest { DraftVersionId = reviewed.Id, DraftUpdatedAtUtc = reviewed.UpdatedAtUtc },
            Publisher, ct));
        Assert.Null((await service.GetAsync(created.Id, ct))!.Published);
    }

    [Fact]
    public async Task Publish_MaxBelowLinkedTemplateDefault_ViolatesInvariant()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "subca", ct);
        await PublishCurrentDraftAsync(service, created.Id, ct);
        await LinkAsync(scope, "SubordinateCA", created.Id, ct); // seeded with ValidityDays = 3650

        await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest { MaxValidityDays = 825 }, Author, ct);

        var ex = await Assert.ThrowsAsync<IssuancePolicyInvariantException>(
            () => PublishCurrentDraftAsync(service, created.Id, ct));
        Assert.Contains("SubordinateCA", ex.Message);
        Assert.Equal(1, (await service.GetAsync(created.Id, ct))!.Published!.VersionNumber);
    }

    [Fact]
    public async Task Archive_WhileLinked_Conflicts_ThenArchivedPolicyRefusesDrafts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "corp", ct);
        await PublishCurrentDraftAsync(service, created.Id, ct);
        await LinkAsync(scope, "WebServer", created.Id, ct);

        await Assert.ThrowsAsync<IssuancePolicyConflictException>(
            () => service.SetArchivedAsync(created.Id, true, Author, ct));

        await LinkAsync(scope, "WebServer", null, ct);
        var archived = await service.SetArchivedAsync(created.Id, true, Author, ct);
        Assert.True(archived!.IsArchived);
        await Assert.ThrowsAsync<IssuancePolicyConflictException>(() => service.SaveDraftAsync(
            created.Id, new SaveIssuancePolicyDraftRequest(), Author, ct));
    }

    [Fact]
    public async Task Delete_Unreferenced_RemovesPolicyAndVersions()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "temp", ct);
        await PublishCurrentDraftAsync(service, created.Id, ct);

        Assert.True(await service.DeleteAsync(created.Id, Author, ct));

        Assert.False(await scope.Db.IssuancePolicies.AnyAsync(ct));
        Assert.False(await scope.Db.IssuancePolicyVersions.AnyAsync(ct));
        Assert.Contains(scope.Audit.Entries, e => e.Action == "IssuancePolicyDeleted" && e.ResourceName == "temp");
    }

    [Fact]
    public async Task Delete_WhileLinked_Conflicts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "corp", ct);
        await PublishCurrentDraftAsync(service, created.Id, ct);
        await LinkAsync(scope, "WebServer", created.Id, ct);

        await Assert.ThrowsAsync<IssuancePolicyConflictException>(() => service.DeleteAsync(created.Id, Author, ct));
    }

    [Fact]
    public async Task Delete_AfterARequestWasAllowedUnderIt_Conflicts()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "corp", ct, dns: ["corp.example.com"]);
        await PublishCurrentDraftAsync(service, created.Id, ct);
        await LinkAsync(scope, "WebServer", created.Id, ct);
        await scope.CreateRequestService().CreateAsync(
            new CertificateRequest { CommonName = "a.corp.example.com", RequestedBy = "alice", Type = "WebServer" }, "alice", ct);
        await LinkAsync(scope, "WebServer", null, ct);

        await Assert.ThrowsAsync<IssuancePolicyConflictException>(() => service.DeleteAsync(created.Id, Author, ct));
    }

    [Fact]
    public async Task DiscardDraft_RemovesOnlyTheDraft()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "corp", ct);
        await PublishCurrentDraftAsync(service, created.Id, ct);
        await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest { MaxValidityDays = 30 }, Author, ct);

        Assert.True(await service.DiscardDraftAsync(created.Id, Author, ct));

        var after = await service.GetAsync(created.Id, ct);
        Assert.Null(after!.Draft);
        Assert.NotNull(after.Published);
        await Assert.ThrowsAsync<IssuancePolicyConflictException>(() => service.DiscardDraftAsync(created.Id, Author, ct));
    }

    [Fact]
    public async Task List_ReportsPublishedVersionDraftAndLinkCount()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await CreateWithRulesAsync(service, "corp", ct);
        await PublishCurrentDraftAsync(service, created.Id, ct);
        await LinkAsync(scope, "WebServer", created.Id, ct);
        await LinkAsync(scope, "ClientAuth", created.Id, ct);

        var summary = Assert.Single(await service.ListAsync(ct));

        Assert.Equal(1, summary.PublishedVersionNumber);
        Assert.False(summary.HasDraft);
        Assert.Equal(2, summary.LinkedTemplateCount);
    }

    [Fact]
    public async Task SaveDraft_KeepsRequesterRoles_TrimmedAndInOrder()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var service = scope.CreateManagementService();
        var created = await service.CreateAsync(new SaveIssuancePolicyRequest { Name = "corp" }, Author, ct);

        var saved = await service.SaveDraftAsync(created.Id, new SaveIssuancePolicyDraftRequest
        {
            AllowedRequesterRoles = ["ops", " pki "]
        }, Author, ct);

        Assert.Equal(["ops", "pki"], saved!.Draft!.AllowedRequesterRoles);
    }

    [Fact]
    public async Task ExistingVersionWithoutRoles_ReadsAsUnrestricted()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        var version = await PolicySeeding.LinkPublishedPolicyAsync(scope.Db, "WebServer", ct: ct);

        Assert.Empty(IssuancePolicyManagementService.ToVersionResponse(version)!.AllowedRequesterRoles);
    }
}
