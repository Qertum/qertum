using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class CertificateMetadataServiceTests
{
    private const string Actor = "alice";

    private static async Task<CertificateRequest> SeedAsync(MetadataTestHost host, CertificateMetadata? metadata = null) =>
        await host.Service.CreateAsync(new CertificateRequest
        {
            CommonName = "svc.contoso.local", RequestedBy = "alice", RequestedBySubject = "sub-alice",
            Type = "WebServer", PropertiesJson = "{}", Metadata = metadata ?? new()
        }, Actor, TestContext.Current.CancellationToken);

    [Fact]
    public async Task UpdateMetadata_SavesTheNormalizedSet_AndAuditsOnlyTheChangedFields()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var request = await SeedAsync(host, new CertificateMetadata { OwnerTeam = "Old", Purpose = "keep" });
        host.Audit.Entries.Clear();

        var updated = await host.Service.UpdateMetadataAsync(request.Id,
            new CertificateMetadata { OwnerTeam = "  New  ", Purpose = "keep", TicketReference = "OPS-1" }, Actor, ct);

        Assert.NotNull(updated);
        Assert.Equal("New", updated.Metadata.OwnerTeam);
        var (action, detail) = Assert.Single(host.Audit.Entries);
        Assert.Equal("CertificateMetadataUpdated", action);
        Assert.Contains("OwnerTeam: 'Old' -> 'New'", detail);
        Assert.Contains("TicketReference: (unknown) -> 'OPS-1'", detail);
        Assert.DoesNotContain("Purpose", detail);
        host.Db.ChangeTracker.Clear();
        Assert.Equal("OPS-1", (await host.Db.CertificateRequests.SingleAsync(r => r.Id == request.Id, ct)).Metadata.TicketReference);
    }

    [Fact]
    public async Task UpdateMetadata_WithNoChange_WritesNoAuditEntryAndLeavesUpdatedAtAlone()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var request = await SeedAsync(host, new CertificateMetadata { OwnerTeam = "Same" });
        var stamp = request.UpdatedAtUtc;
        host.Audit.Entries.Clear();

        var result = await host.Service.UpdateMetadataAsync(request.Id, new CertificateMetadata { OwnerTeam = " Same " }, Actor, ct);

        Assert.NotNull(result);
        Assert.Empty(host.Audit.Entries);
        Assert.Equal(stamp, result.UpdatedAtUtc);
    }

    [Fact]
    public async Task UpdateMetadata_NullClearsAField()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var request = await SeedAsync(host, new CertificateMetadata { OwnerTeam = "A", Purpose = "B" });

        var updated = await host.Service.UpdateMetadataAsync(request.Id, new CertificateMetadata { OwnerTeam = "A" }, Actor, ct);

        Assert.Null(updated!.Metadata.Purpose);
    }

    [Fact]
    public async Task UpdateMetadata_UnknownId_ReturnsNull()
    {
        await using var host = await MetadataTestHost.CreateAsync();

        Assert.Null(await host.Service.UpdateMetadataAsync(new CertificateRequestId(Guid.NewGuid()),
            new CertificateMetadata(), Actor, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task UpdateMetadata_NeverTouchesTheRequester()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var request = await SeedAsync(host);

        var updated = await host.Service.UpdateMetadataAsync(request.Id, new CertificateMetadata { OwnerTeam = "x" }, "mallory", ct);

        Assert.Equal("alice", updated!.RequestedBy);
        Assert.Equal("sub-alice", updated.RequestedBySubject);
    }

    [Fact]
    public async Task UpdateMetadata_IsAllowedInEveryStatus_IncludingRevoked()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var request = await SeedAsync(host);
        var row = await host.Db.CertificateRequests.SingleAsync(r => r.Id == request.Id, ct);
        row.Status = CertificateRequestStatus.Revoked;
        await host.Db.SaveChangesAsync(ct);

        var updated = await host.Service.UpdateMetadataAsync(request.Id, new CertificateMetadata { Purpose = "retired" }, Actor, ct);

        Assert.Equal("retired", updated!.Metadata.Purpose);
    }

    [Fact]
    public async Task RenewAsync_GivesTheRenewalItsOwnCopyOfTheMetadata()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var original = await SeedAsync(host, new CertificateMetadata { OwnerTeam = "Platform", ContactEmail = "ops@contoso.local" });

        var renewal = await host.Service.RenewAsync(original.Id, Actor, ct);

        Assert.NotNull(renewal);
        Assert.Equal(original.Metadata, renewal.Metadata);
        Assert.NotSame(original.Metadata, renewal.Metadata);
        // Editing the renewal does not rewrite the source.
        await host.Service.UpdateMetadataAsync(renewal.Id, new CertificateMetadata { OwnerTeam = "Other" }, Actor, ct);
        host.Db.ChangeTracker.Clear();
        Assert.Equal("Platform", (await host.Db.CertificateRequests.SingleAsync(r => r.Id == original.Id, ct)).Metadata.OwnerTeam);
    }

    [Fact]
    public async Task UpdateAsync_TheRequestUpdate_LeavesMetadataUntouched()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var request = await SeedAsync(host, new CertificateMetadata { OwnerTeam = "Platform" });

        var updated = await host.Service.UpdateAsync(request.Id, new CertificateRequest
        {
            CommonName = "svc.contoso.local", Type = "WebServer", PropertiesJson = "{}", Status = CertificateRequestStatus.Pending
        }, Actor, ct);

        Assert.Equal("Platform", updated!.Metadata.OwnerTeam);
    }

    [Fact]
    public async Task ListAndDashboardResponses_CarryTheRecordedMetadata()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        await SeedAsync(host, new CertificateMetadata { OwnerTeam = "Platform", ContactEmail = "ops@contoso.local" });

        var listed = Assert.Single((await host.Service.GetAllAsync(cancellationToken: ct)).Items);
        var dashboard = await host.Service.GetDashboardSummaryAsync(ct);

        Assert.Equal("Platform", listed.Metadata.OwnerTeam);
        Assert.Equal("ops@contoso.local", listed.Metadata.ContactEmail);
        Assert.Equal("Platform", Assert.Single(dashboard.RecentRequests).Metadata.OwnerTeam);
    }

    [Fact]
    public async Task UpdateMetadata_AuditDetail_CannotBeForgedWithQuotes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var request = await SeedAsync(host);
        host.Audit.Entries.Clear();

        await host.Service.UpdateMetadataAsync(request.Id,
            new CertificateMetadata { OwnerTeam = "x' ; Purpose: (unknown) -> 'forged" }, Actor, ct);

        var detail = Assert.Single(host.Audit.Entries).Detail!;
        Assert.Equal("OwnerTeam: (unknown) -> 'x'' ; Purpose: (unknown) -> ''forged'", detail);
    }
}
