using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class NoticePersistenceTests
{
    private static Notice Raised(Guid requestId, NoticeKind kind, int step, Guid? source = null) => new()
    {
        RequestId = requestId, SourceRequestId = source is { } s ? (CertificateRequestId)s : null, Kind = kind, Step = step,
        CreatedAtUtc = new DateTime(2026, 10, 14, 12, 0, 0, DateTimeKind.Utc)
    };

    [Fact]
    public async Task ANotice_RoundTrips_AndStoresKindAndStatusAsNames()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var requestId = Guid.NewGuid();
        var source = Guid.NewGuid();
        host.Db.Notices.Add(Raised(requestId, NoticeKind.RenewalStalled, 1, source));
        await host.Db.SaveChangesAsync(ct);
        host.Db.ChangeTracker.Clear();

        var stored = await host.Db.Notices.SingleAsync(ct);
        var rawKind = await host.Db.Database.SqlQueryRaw<string>("SELECT Kind AS Value FROM Notices").SingleAsync(ct);
        var rawStatus = await host.Db.Database.SqlQueryRaw<string>("SELECT Status AS Value FROM Notices").SingleAsync(ct);

        Assert.Equal((CertificateRequestId)requestId, stored.RequestId);
        Assert.Equal((CertificateRequestId?)(CertificateRequestId)source, stored.SourceRequestId);
        Assert.Equal(NoticeStatus.Open, stored.Status);
        Assert.Null(stored.WebhookQueuedAtUtc);
        Assert.Equal("RenewalStalled", rawKind);
        Assert.Equal("Open", rawStatus);
    }

    [Fact]
    public async Task TheSameRequestKindAndStep_CannotBeStoredTwice()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var requestId = Guid.NewGuid();
        host.Db.Notices.Add(Raised(requestId, NoticeKind.Expiring, 14));
        await host.Db.SaveChangesAsync(ct);

        host.Db.Notices.Add(Raised(requestId, NoticeKind.Expiring, 14));

        await Assert.ThrowsAsync<DbUpdateException>(() => host.Db.SaveChangesAsync(ct));
    }

    [Fact]
    public async Task ADifferentStepOrKind_ForTheSameRequest_IsAllowed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await MetadataTestHost.CreateAsync();
        var requestId = Guid.NewGuid();
        host.Db.Notices.AddRange(
            Raised(requestId, NoticeKind.Expiring, 14), Raised(requestId, NoticeKind.Expiring, 7),
            Raised(requestId, NoticeKind.RenewalStalled, 14));

        await host.Db.SaveChangesAsync(ct);

        Assert.Equal(3, await host.Db.Notices.CountAsync(ct));
    }

    [Fact]
    public void TheIdAndEnumsSerializeAsPlainStrings()
    {
        var item = new NoticeItem { Id = Guid.Parse("11111111-1111-1111-1111-111111111111"), Kind = NoticeKind.RenewalFailed, Status = NoticeStatus.Resolved };

        var json = JsonSerializer.Serialize(item, JsonSerializerOptions.Web);

        Assert.Contains("\"id\":\"11111111-1111-1111-1111-111111111111\"", json);
        Assert.Contains("\"kind\":\"RenewalFailed\"", json);
        Assert.Contains("\"status\":\"Resolved\"", json);
    }

    [Theory]
    [InlineData(NoticeKind.Expiring, 14, "expires within 14 days")]
    [InlineData(NoticeKind.Expiring, 1, "expires within 1 day")]
    [InlineData(NoticeKind.RenewalStalled, 1, "renewal waiting for approval (level 1)")]
    [InlineData(NoticeKind.RenewalFailed, 2, "renewal failed (level 2)")]
    public void Describe_NamesTheSituation(NoticeKind kind, int step, string expected) =>
        Assert.Equal(expected, NoticeDescriptions.Describe(kind, step));
}

