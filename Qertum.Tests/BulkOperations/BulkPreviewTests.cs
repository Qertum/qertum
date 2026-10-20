using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.BulkOperations;

namespace Qertum.Tests.BulkOperations;

public sealed class BulkPreviewTests
{
    private static PreviewBulkOperationRequest Revoke(BulkOperationFilter filter) =>
        new(BulkOperationKind.Revoke, filter, "key compromise");

    private static PreviewBulkOperationRequest Renew(BulkOperationFilter filter) =>
        new(BulkOperationKind.Renew, filter);

    [Fact]
    public async Task EmptyFilter_IsRefused_AndWritesNothing()
    {
        await using var scope = await BulkScope.CreateAsync();
        var ex = await Assert.ThrowsAsync<BulkOperationException>(() =>
            scope.CreateService().PreviewAsync(Revoke(new BulkOperationFilter()), BulkScope.Operator, TestContext.Current.CancellationToken));
        Assert.Equal(422, ex.StatusCode);
        await using var db = scope.NewDb();
        Assert.Empty(await db.BulkOperations.ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AllCombinedWithACriterion_IsRefused()
    {
        await using var scope = await BulkScope.CreateAsync();
        var ex = await Assert.ThrowsAsync<BulkOperationException>(() =>
            scope.CreateService().PreviewAsync(Revoke(new BulkOperationFilter { All = true, TemplateKey = "WebServer" }), BulkScope.Operator, TestContext.Current.CancellationToken));
        Assert.Equal(422, ex.StatusCode);
    }

    [Fact]
    public async Task RevokeWithoutReason_IsRefused()
    {
        await using var scope = await BulkScope.CreateAsync();
        var ex = await Assert.ThrowsAsync<BulkOperationException>(() =>
            scope.CreateService().PreviewAsync(new(BulkOperationKind.Revoke, new BulkOperationFilter { All = true }, "  "), BulkScope.Operator, TestContext.Current.CancellationToken));
        Assert.Equal(422, ex.StatusCode);
    }

    [Fact]
    public async Task All_FreezesEveryIssuedRequest_AndCountsTheRestAsNotIssued()
    {
        await using var scope = await BulkScope.CreateAsync();
        await scope.AddIssuedAsync("a.example");
        await scope.AddIssuedAsync("b.example");
        await scope.AddIssuedAsync("pending.example", status: CertificateRequestStatus.Pending);

        var preview = await scope.CreateService().PreviewAsync(Revoke(new BulkOperationFilter { All = true }), BulkScope.Operator, TestContext.Current.CancellationToken);

        Assert.Equal(2, preview.Operation.ItemCount);
        Assert.Equal(BulkOperationStatus.Previewed, preview.Operation.Status);
        Assert.Equal(1, preview.Operation.Excluded["not-issued"]);
        Assert.Equal(2, preview.Sample.Count);
        await using var db = scope.NewDb();
        Assert.Equal(2, await db.BulkOperationItems.CountAsync(TestContext.Current.CancellationToken));
        Assert.Contains(scope.Audit.Entries, e => e.Action == "BulkOperationPreviewed" && e.PerformedBy == "operator");
    }

    [Fact]
    public async Task EachCriterion_NarrowsTheSet()
    {
        await using var scope = await BulkScope.CreateAsync();
        var issuer = new IssuerId(Guid.NewGuid());
        await scope.AddIssuedAsync("in-issuer.example", issuerId: issuer);
        await scope.AddIssuedAsync("other.example");
        await scope.AddIssuedAsync("mine.example", ownerSubject: "sub-1");
        await scope.AddIssuedAsync("mail.example", type: "Smime");
        await scope.AddIssuedAsync("soon.example", validTo: scope.Clock.GetUtcNow().UtcDateTime.AddDays(5));
        var service = scope.CreateService();

        Assert.Equal(1, (await service.PreviewAsync(Revoke(new BulkOperationFilter { IssuerId = issuer }), BulkScope.Operator, TestContext.Current.CancellationToken)).Operation.ItemCount);
        Assert.Equal(1, (await service.PreviewAsync(Revoke(new BulkOperationFilter { OwnerSubject = "sub-1" }), BulkScope.Operator, TestContext.Current.CancellationToken)).Operation.ItemCount);
        Assert.Equal(1, (await service.PreviewAsync(Revoke(new BulkOperationFilter { TemplateKey = "Smime" }), BulkScope.Operator, TestContext.Current.CancellationToken)).Operation.ItemCount);
        Assert.Equal(1, (await service.PreviewAsync(Revoke(new BulkOperationFilter { ExpiresWithinDays = 30 }), BulkScope.Operator, TestContext.Current.CancellationToken)).Operation.ItemCount);
        Assert.Equal(1, (await service.PreviewAsync(Revoke(new BulkOperationFilter { CommonNameContains = "mail." }), BulkScope.Operator, TestContext.Current.CancellationToken)).Operation.ItemCount);
    }

    [Fact]
    public async Task CommonNameContains_MatchesPercentAndUnderscoreLiterally()
    {
        await using var scope = await BulkScope.CreateAsync();
        await scope.AddIssuedAsync("a_b.example");
        await scope.AddIssuedAsync("axb.example");

        var preview = await scope.CreateService().PreviewAsync(
            Revoke(new BulkOperationFilter { CommonNameContains = "a_b" }), BulkScope.Operator, TestContext.Current.CancellationToken);

        Assert.Equal(1, preview.Operation.ItemCount);
    }

    [Fact]
    public async Task NothingEligible_IsRefusedNamingTheExclusions()
    {
        await using var scope = await BulkScope.CreateAsync();
        await scope.AddIssuedAsync("pending.example", status: CertificateRequestStatus.Pending);

        var ex = await Assert.ThrowsAsync<BulkOperationException>(() =>
            scope.CreateService().PreviewAsync(Revoke(new BulkOperationFilter { All = true }), BulkScope.Operator, TestContext.Current.CancellationToken));

        Assert.Equal(422, ex.StatusCode);
        Assert.Contains("not-issued", ex.Detail);
        await using var db = scope.NewDb();
        Assert.Empty(await db.BulkOperations.ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task OverTheCap_IsRefusedWithTheCount_AndWritesNothing()
    {
        await using var scope = await BulkScope.CreateAsync();
        for (var i = 0; i < 3; i++) await scope.AddIssuedAsync($"n{i}.example");

        var ex = await Assert.ThrowsAsync<BulkOperationException>(() =>
            scope.CreateService(new BulkOperationsOptions { MaxItems = 2 })
                .PreviewAsync(Revoke(new BulkOperationFilter { All = true }), BulkScope.Operator, TestContext.Current.CancellationToken));

        Assert.Equal(422, ex.StatusCode);
        Assert.Contains("3", ex.Detail);
        await using var db = scope.NewDb();
        Assert.Empty(await db.BulkOperations.ToListAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Renew_ExcludesActiveRenewals_CaCapableTemplates_AndClientKeys()
    {
        await using var scope = await BulkScope.CreateAsync();
        await scope.AddCaTemplateAsync("SubordinateCA");
        await scope.AddIssuedAsync("ok.example");
        var renewed = await scope.AddIssuedAsync("renewed.example");
        await scope.AddRenewalOfAsync(renewed, CertificateRequestStatus.Pending);
        var rejectedRenewal = await scope.AddIssuedAsync("rejected-renewal.example");
        await scope.AddRenewalOfAsync(rejectedRenewal, CertificateRequestStatus.Rejected);
        await scope.AddIssuedAsync("ca.example", type: "SubordinateCA");
        await scope.AddIssuedAsync("acme.example", csrPem: "-----BEGIN CERTIFICATE REQUEST-----");

        var preview = await scope.CreateService().PreviewAsync(Renew(new BulkOperationFilter { All = true }), BulkScope.Operator, TestContext.Current.CancellationToken);

        Assert.Equal(2, preview.Operation.ItemCount); // ok + rejected-renewal
        Assert.Equal(1, preview.Operation.Excluded["active-renewal"]);
        Assert.Equal(1, preview.Operation.Excluded["ca-capable"]);
        Assert.Equal(1, preview.Operation.Excluded["client-key"]);
    }

    [Fact]
    public async Task Revoke_DoesNotApplyTheRenewOnlyExclusions()
    {
        await using var scope = await BulkScope.CreateAsync();
        await scope.AddCaTemplateAsync("SubordinateCA");
        await scope.AddIssuedAsync("ca.example", type: "SubordinateCA");
        await scope.AddIssuedAsync("acme.example", csrPem: "x");

        var preview = await scope.CreateService().PreviewAsync(Revoke(new BulkOperationFilter { All = true }), BulkScope.Operator, TestContext.Current.CancellationToken);

        Assert.Equal(2, preview.Operation.ItemCount);
    }
}
