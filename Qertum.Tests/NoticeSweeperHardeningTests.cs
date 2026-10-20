using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Notices;

namespace Qertum.Tests;

/// <summary>Findings of the whole-branch review, each pinned against the real webhook service where that is the point.</summary>
public sealed class NoticeSweeperHardeningTests
{
    private static async Task SubscribeAsync(NoticeTestHost host)
    {
        host.Db.Webhooks.Add(new Webhook
        {
            Id = Guid.NewGuid(), Name = "notices", Url = "https://hooks.contoso.local/notices", Family = WebhookEventFamily.Notice,
            EventsJson = "[]", IsEnabled = true, CreatedAtUtc = host.Now, UpdatedAtUtc = host.Now
        });
        await host.Db.SaveChangesAsync(TestContext.Current.CancellationToken);
    }

    private static Task<int> DeliveriesAsync(NoticeTestHost host) =>
        host.Db.WebhookDeliveries.AsNoTracking().CountAsync(TestContext.Current.CancellationToken);

    // ── The real WebhookService swallows failures; the sweeper must still know ─────────────────────

    [Fact]
    public async Task ARealWebhookFailure_LeavesTheNoticeUnqueued_AndTheNextSweepDeliversExactlyOnce()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoticeTestHost.CreateAsync(realWebhooks: true);
        await SubscribeAsync(host);
        await host.IssuedAsync("a.contoso.local", validInDays: 10);
        var ddl = await host.Db.Database.SqlQueryRaw<string>(
            "SELECT sql AS Value FROM sqlite_master WHERE type = 'table' AND name = 'WebhookDeliveries'").SingleAsync(ct);
        await host.Db.Database.ExecuteSqlRawAsync("DROP TABLE WebhookDeliveries", ct);   // the delivery store is down

        await Assert.ThrowsAnyAsync<Exception>(() => host.SweepAsync());

        Assert.Null(Assert.Single(await host.NoticesAsync()).WebhookQueuedAtUtc);

        await host.Db.Database.ExecuteSqlRawAsync(ddl, ct);                              // it comes back
        var retry = await host.SweepAsync();

        Assert.Equal(1, retry.Queued);
        Assert.NotNull(Assert.Single(await host.NoticesAsync()).WebhookQueuedAtUtc);
        Assert.Equal(1, await DeliveriesAsync(host));
    }

    [Fact]
    public async Task ARealWebhookWithASubscriber_WritesOneDelivery_CarryingTheContact()
    {
        await using var host = await NoticeTestHost.CreateAsync(realWebhooks: true);
        await SubscribeAsync(host);
        await host.IssuedAsync("a.contoso.local", validInDays: 10, new CertificateMetadata { ContactEmail = "ops@contoso.local" });

        await host.SweepAsync();

        var delivery = await host.Db.WebhookDeliveries.AsNoTracking().SingleAsync(TestContext.Current.CancellationToken);
        Assert.Equal(WellKnownWebhookEvents.CertificateExpiring, delivery.EventType);
        Assert.Contains("ops@contoso.local", delivery.Payload);
    }

    [Fact]
    public async Task WithNoSubscriber_TheNoticeIsStillStamped_AndALaterWebhookDoesNotReceiveIt()
    {
        await using var host = await NoticeTestHost.CreateAsync(realWebhooks: true);
        await host.IssuedAsync("a.contoso.local", validInDays: 10);

        await host.SweepAsync();
        await SubscribeAsync(host);
        await host.SweepAsync();

        Assert.NotNull(Assert.Single(await host.NoticesAsync()).WebhookQueuedAtUtc);
        Assert.Equal(0, await DeliveriesAsync(host));
    }

    // ── Pruning must not delete the once-only record while the situation holds ──────────────────────

    [Fact]
    public async Task APrunedSupersededLevel_IsNotRaisedAgain_WhileTheRenewalIsStillStalled()
    {
        await using var host = await NoticeTestHost.CreateAsync(new NoticesOptions { RetentionDays = 1 });
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 400);
        await host.RenewalAsync(cert, CertificateRequestStatus.Pending, createdHoursAgo: 80);
        await host.SweepAsync();                                   // level 1
        host.Clock.Advance(TimeSpan.FromHours(25));
        await host.SweepAsync();                                   // level 2; level 1 resolved

        host.Clock.Advance(TimeSpan.FromDays(3));
        await host.SweepAsync();                                   // retention has passed for level 1

        var notices = await host.NoticesAsync();
        Assert.Equal([1, 2], notices.Select(n => n.Step).Order());
        Assert.Equal(NoticeStatus.Resolved, notices.Single(n => n.Step == 1).Status);
        Assert.Equal(NoticeStatus.Open, notices.Single(n => n.Step == 2).Status);
        Assert.Equal(2, host.Webhooks.Events.Count);
    }

    // ── A superseded sibling that stayed open is closed on the next sweep ───────────────────────────

    [Fact]
    public async Task AnOpenLessUrgentSibling_IsClosed_WhenAMoreUrgentOneIsOpen()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 5);
        foreach (var step in new[] { 14, 7 })
        {
            host.Db.Notices.Add(new Notice
            {
                RequestId = cert.Id, Kind = NoticeKind.Expiring, Step = step, CreatedAtUtc = host.Now.AddHours(-step),
                WebhookQueuedAtUtc = host.Now.AddHours(-step)
            });
        }
        await host.Db.SaveChangesAsync(TestContext.Current.CancellationToken);

        await host.SweepAsync();

        var notices = await host.NoticesAsync();
        Assert.Equal(NoticeStatus.Resolved, notices.Single(n => n.Step == 14).Status);
        Assert.Equal(NoticeStatus.Open, notices.Single(n => n.Step == 7).Status);
    }

    // ── CA certificates are renewed by ceremony, not noticed ────────────────────────────────────────

    [Theory]
    [InlineData("RootCA", false)]
    [InlineData("SubordinateCA", false)]
    [InlineData("WebServer", true)]
    public async Task Expiring_IsNotRaised_ForCaCertificates(string type, bool raised)
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 10, type: type);

        await host.SweepAsync();

        Assert.Equal(raised, (await host.NoticesAsync()).Count == 1);
    }

    // ── The renewal lookups need an index ───────────────────────────────────────────────────────────

    [Fact]
    public async Task TheRenewalLookup_HasAnIndex()
    {
        await using var host = await NoticeTestHost.CreateAsync();

        var indexes = host.Db.Model.FindEntityType(typeof(CertificateRequest))!.GetIndexes()
            .Select(i => string.Join(",", i.Properties.Select(p => p.Name)));

        Assert.Contains("RenewedFromId,Status", indexes);
    }
}
