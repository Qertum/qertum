using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Notices;

namespace Qertum.Tests;

public sealed class NoticeSweeperTests
{
    // ── Expiring ───────────────────────────────────────────────────────────────

    [Fact]
    public async Task Expiring_RaisesTheSmallestCrossedThreshold_AndQueuesOneWebhook()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10);

        var result = await host.SweepAsync();

        var notice = Assert.Single(await host.NoticesAsync());
        Assert.Equal((NoticeKind.Expiring, 14, NoticeStatus.Open, cert.Id), (notice.Kind, notice.Step, notice.Status, notice.RequestId));
        Assert.NotNull(notice.WebhookQueuedAtUtc);
        Assert.Equal(1, result.Raised);
        Assert.Equal(WellKnownWebhookEvents.CertificateExpiring, Assert.Single(host.Webhooks.Events).EventType);
    }

    [Fact]
    public async Task Expiring_AfterDowntime_RaisesOnlyTheMostUrgentThreshold()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 3);

        await host.SweepAsync();

        Assert.Equal(7, Assert.Single(await host.NoticesAsync()).Step);
    }

    [Fact]
    public async Task Expiring_FiresOncePerStep_AcrossRepeatedSweeps()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 10);

        await host.SweepAsync();
        host.Clock.Advance(TimeSpan.FromHours(2));
        var second = await host.SweepAsync();

        Assert.Single(await host.NoticesAsync());
        Assert.Single(host.Webhooks.Events);
        Assert.Equal(0, second.Raised);
        Assert.Equal(0, second.Queued);
    }

    [Fact]
    public async Task Expiring_ANextThreshold_SupersedesTheOlderNotice()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 10);
        await host.SweepAsync();

        host.Clock.Advance(TimeSpan.FromDays(4));   // 6 days left: inside 7
        await host.SweepAsync();

        var notices = await host.NoticesAsync();
        Assert.Equal(NoticeStatus.Resolved, notices.Single(n => n.Step == 14).Status);
        Assert.Equal(NoticeStatus.Open, notices.Single(n => n.Step == 7).Status);
        Assert.Equal(2, host.Webhooks.Events.Count);
    }

    [Fact]
    public async Task Expiring_IsNotRaised_ForAFarOrAnAlreadyExpiredCertificate()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("far.contoso.local", validInDays: 90);
        await host.IssuedAsync("gone.contoso.local", validInDays: -2);

        await host.SweepAsync();

        Assert.Empty(await host.NoticesAsync());
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Pending)]
    [InlineData(CertificateRequestStatus.Approved)]
    [InlineData(CertificateRequestStatus.Processing)]
    [InlineData(CertificateRequestStatus.Issued)]
    public async Task Expiring_IsNotRaised_WhileARenewalIsInFlightOrIssued(CertificateRequestStatus renewalStatus)
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10);
        await host.RenewalAsync(cert, renewalStatus);

        await host.SweepAsync();

        Assert.DoesNotContain(await host.NoticesAsync(), n => n.Kind == NoticeKind.Expiring);
    }

    [Fact]
    public async Task Expiring_IsStillRaised_WhenTheOnlyRenewalWasRejected()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10);
        await host.RenewalAsync(cert, CertificateRequestStatus.Rejected, failureReason: "boom", updatedHoursAgo: 500);

        await host.SweepAsync();

        Assert.Contains(await host.NoticesAsync(), n => n.Kind == NoticeKind.Expiring);
    }

    [Fact]
    public async Task Expiring_Resolves_WhenARenewalIsIssued()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10);
        await host.SweepAsync();
        await host.RenewalAsync(cert, CertificateRequestStatus.Issued);

        var result = await host.SweepAsync();

        Assert.Equal(NoticeStatus.Resolved, Assert.Single(await host.NoticesAsync()).Status);
        Assert.Equal(1, result.Resolved);
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Revoked)]
    [InlineData(CertificateRequestStatus.PendingRevocation)]
    public async Task Expiring_Resolves_WhenTheCertificateIsRevoked(CertificateRequestStatus status)
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10);
        await host.SweepAsync();
        await host.SetStatusAsync(cert, status);

        await host.SweepAsync();

        Assert.Equal(NoticeStatus.Resolved, Assert.Single(await host.NoticesAsync()).Status);
    }

    [Fact]
    public async Task Expiring_Resolves_OnceTheCertificateHasBeenExpiredPastTheGrace()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 1);
        await host.SweepAsync();

        host.Clock.Advance(TimeSpan.FromDays(2));     // expired a day ago: still open
        await host.SweepAsync();
        Assert.Equal(NoticeStatus.Open, Assert.Single(await host.NoticesAsync()).Status);

        host.Clock.Advance(TimeSpan.FromDays(7));     // expired more than the grace ago
        await host.SweepAsync();
        Assert.Equal(NoticeStatus.Resolved, Assert.Single(await host.NoticesAsync()).Status);
    }

    [Fact]
    public async Task Expiring_Resolves_WhenTheRequestWasDeleted()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10);
        await host.SweepAsync();
        host.Db.CertificateRequests.Remove(cert);
        await host.Db.SaveChangesAsync(TestContext.Current.CancellationToken);

        await host.SweepAsync();

        Assert.Equal(NoticeStatus.Resolved, Assert.Single(await host.NoticesAsync()).Status);
    }

    // ── Stalled ────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Stalled_IsNotRaised_BeforeTheAttentionAge()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        await host.RenewalAsync(cert, CertificateRequestStatus.Pending, createdHoursAgo: 71);

        await host.SweepAsync();

        Assert.Empty(await host.NoticesAsync());
    }

    [Fact]
    public async Task Stalled_Level1_IsRaisedAfterTheAttentionAge_ForTheRenewal()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        var renewal = await host.RenewalAsync(cert, CertificateRequestStatus.Pending, createdHoursAgo: 73);

        await host.SweepAsync();

        var notice = Assert.Single(await host.NoticesAsync());
        Assert.Equal((NoticeKind.RenewalStalled, 1, renewal.Id, (CertificateRequestId?)cert.Id),
            (notice.Kind, notice.Step, notice.RequestId, notice.SourceRequestId));
        Assert.Equal(WellKnownWebhookEvents.RenewalStalled, Assert.Single(host.Webhooks.Events).EventType);
    }

    [Fact]
    public async Task Stalled_IsNotRaised_ForAPendingRequestThatIsNotARenewal()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        host.Db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = "new.contoso.local", RequestedBy = "alice", Status = CertificateRequestStatus.Pending,
            CreatedAtUtc = host.Now.AddDays(-10)
        });
        await host.Db.SaveChangesAsync(TestContext.Current.CancellationToken);

        await host.SweepAsync();

        Assert.Empty(await host.NoticesAsync());
    }

    [Fact]
    public async Task Stalled_EscalatesToLevel2_AfterTheGap_AndClosesLevel1()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        await host.RenewalAsync(cert, CertificateRequestStatus.Pending, createdHoursAgo: 80);
        await host.SweepAsync();

        host.Clock.Advance(TimeSpan.FromHours(23));
        await host.SweepAsync();
        Assert.Single(await host.NoticesAsync());               // not yet

        host.Clock.Advance(TimeSpan.FromHours(2));              // 25 h since level 1
        await host.SweepAsync();

        var notices = await host.NoticesAsync();
        Assert.Equal(NoticeStatus.Resolved, notices.Single(n => n.Step == 1).Status);
        Assert.Equal(NoticeStatus.Open, notices.Single(n => n.Step == 2).Status);
        Assert.Equal(2, host.Webhooks.Events.Count);
    }

    [Fact]
    public async Task Stalled_DoesNotRepeatBeyondLevel2()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        await host.RenewalAsync(cert, CertificateRequestStatus.Pending, createdHoursAgo: 80);
        await host.SweepAsync();
        host.Clock.Advance(TimeSpan.FromHours(25));
        await host.SweepAsync();

        host.Clock.Advance(TimeSpan.FromDays(10));
        await host.SweepAsync();

        Assert.Equal(2, (await host.NoticesAsync()).Count);
        Assert.Equal(2, host.Webhooks.Events.Count);
    }

    [Theory]
    [InlineData(CertificateRequestStatus.Approved)]
    [InlineData(CertificateRequestStatus.Rejected)]
    [InlineData(CertificateRequestStatus.Issued)]
    public async Task Stalled_Resolves_WhenTheRenewalLeavesPending(CertificateRequestStatus status)
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        var renewal = await host.RenewalAsync(cert, CertificateRequestStatus.Pending, createdHoursAgo: 80);
        await host.SweepAsync();
        await host.SetStatusAsync(renewal, status);

        await host.SweepAsync();

        Assert.Equal(NoticeStatus.Resolved, Assert.Single(await host.NoticesAsync(), n => n.Kind == NoticeKind.RenewalStalled).Status);
    }

    // ── Failed ─────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Failed_Level1_IsRaised_ForARejectedRenewalWithAFailureReason()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        var renewal = await host.RenewalAsync(cert, CertificateRequestStatus.Rejected, failureReason: "CA unavailable", updatedHoursAgo: 2);

        await host.SweepAsync();

        var notice = Assert.Single(await host.NoticesAsync());
        Assert.Equal((NoticeKind.RenewalFailed, 1, renewal.Id), (notice.Kind, notice.Step, notice.RequestId));
        var sent = Assert.Single(host.Webhooks.Events);
        Assert.Equal(WellKnownWebhookEvents.RenewalFailed, sent.EventType);
        Assert.Equal("CA unavailable", sent.Fields!["failureReason"]);
    }

    [Fact]
    public async Task Failed_IsNotRaised_ForAHumanRejection_OrOutsideTheLookback()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        await host.RenewalAsync(cert, CertificateRequestStatus.Rejected, failureReason: null, updatedHoursAgo: 2);
        var other = await host.IssuedAsync("b.contoso.local", validInDays: 100);
        await host.RenewalAsync(other, CertificateRequestStatus.Rejected, failureReason: "old", updatedHoursAgo: 24 * 8);

        await host.SweepAsync();

        Assert.Empty(await host.NoticesAsync());
    }

    [Fact]
    public async Task Failed_Resolves_WhenANewerRenewalOfTheSameCertificateExists()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        await host.RenewalAsync(cert, CertificateRequestStatus.Rejected, createdHoursAgo: 5, failureReason: "boom", updatedHoursAgo: 4);
        await host.SweepAsync();

        await host.RenewalAsync(cert, CertificateRequestStatus.Pending);
        await host.SweepAsync();

        Assert.Equal(NoticeStatus.Resolved, Assert.Single(await host.NoticesAsync(), n => n.Kind == NoticeKind.RenewalFailed).Status);
    }

    [Fact]
    public async Task Failed_EscalatesToLevel2_AfterTheGap()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 100);
        await host.RenewalAsync(cert, CertificateRequestStatus.Rejected, failureReason: "boom", updatedHoursAgo: 1);
        await host.SweepAsync();

        host.Clock.Advance(TimeSpan.FromHours(25));
        await host.SweepAsync();

        var notices = await host.NoticesAsync();
        Assert.Equal(NoticeStatus.Resolved, notices.Single(n => n.Step == 1).Status);
        Assert.Equal(NoticeStatus.Open, notices.Single(n => n.Step == 2).Status);
    }

    // ── Delivery, audit, payload, pruning ──────────────────────────────────────

    [Fact]
    public async Task ACrashBetweenInsertAndQueue_LosesNothing_AndDuplicatesNothing()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 10);
        host.Webhooks.FailNext = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => host.SweepAsync());
        var afterCrash = Assert.Single(await host.NoticesAsync());
        Assert.Null(afterCrash.WebhookQueuedAtUtc);
        Assert.Empty(host.Webhooks.Events);

        var retry = await host.SweepAsync();

        Assert.Single(await host.NoticesAsync());
        Assert.Single(host.Webhooks.Events);
        Assert.Equal(1, retry.Queued);
        Assert.Equal(0, retry.Raised);
    }

    [Fact]
    public async Task TheExpiringPayload_CarriesDaysLeftTheContactAndLevelOne()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10, new CertificateMetadata
        {
            OwnerTeam = "Platform", ContactEmail = "ops@contoso.local", TargetSystem = "gw", TicketReference = "OPS-1"
        });

        await host.SweepAsync();

        var sent = Assert.Single(host.Webhooks.Events);
        var fields = sent.Fields!;
        Assert.Equal((Guid)cert.Id, sent.ResourceId);
        Assert.Equal("a.contoso.local", fields["commonName"]);
        Assert.Equal("10", fields["daysLeft"]);
        Assert.Equal("1", fields["level"]);
        Assert.Equal("Platform", fields["ownerTeam"]);
        Assert.Equal("ops@contoso.local", fields["contactEmail"]);
        Assert.Equal("gw", fields["targetSystem"]);
        Assert.Equal("OPS-1", fields["ticketReference"]);
        Assert.Null(fields["renewalId"]);
    }

    [Fact]
    public async Task TheStalledPayload_NamesTheRenewal_AndTakesExpiryFromTheCertificateBeingRenewed()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 20, new CertificateMetadata { ContactEmail = "ops@contoso.local" });
        var renewal = await host.RenewalAsync(cert, CertificateRequestStatus.Pending, createdHoursAgo: 80);

        await host.SweepAsync();

        var fields = Assert.Single(host.Webhooks.Events, e => e.EventType == WellKnownWebhookEvents.RenewalStalled).Fields!;
        Assert.Equal(renewal.Id.ToString(), fields["renewalId"]);
        Assert.Equal("20", fields["daysLeft"]);
        Assert.Equal("1", fields["level"]);
        Assert.Equal("ops@contoso.local", fields["contactEmail"]);
    }

    [Fact]
    public async Task ACertificateWithNoRecordedContact_StillGetsANotice_WithUnknownContactFields()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 10);

        await host.SweepAsync();

        var fields = Assert.Single(host.Webhooks.Events).Fields!;
        Assert.Null(fields["contactEmail"]);
        Assert.Null(fields["ownerTeam"]);
    }

    [Fact]
    public async Task EachRaise_IsAuditedOnce_AsTheScheduler()
    {
        await using var host = await NoticeTestHost.CreateAsync();
        await host.IssuedAsync("a.contoso.local", validInDays: 10);

        await host.SweepAsync();
        await host.SweepAsync();

        var (action, detail) = Assert.Single(host.Audit.Entries);
        Assert.Equal("NoticeRaised", action);
        Assert.Contains("Expiring", detail);
        Assert.Contains("14", detail);
    }

    [Fact]
    public async Task ResolvedNotices_PastTheRetention_AreDeleted_OthersKept()
    {
        await using var host = await NoticeTestHost.CreateAsync(new NoticesOptions { RetentionDays = 30 });
        var cert = await host.IssuedAsync("a.contoso.local", validInDays: 10);
        await host.SweepAsync();
        await host.RenewalAsync(cert, CertificateRequestStatus.Issued);
        await host.SweepAsync();                                  // resolved now

        host.Clock.Advance(TimeSpan.FromDays(29));
        var early = await host.SweepAsync();
        host.Clock.Advance(TimeSpan.FromDays(2));
        var late = await host.SweepAsync();

        Assert.Equal(0, early.Pruned);
        Assert.Equal(1, late.Pruned);
        Assert.Empty(await host.NoticesAsync());
    }

    [Fact]
    public async Task AnOpenNotice_IsNeverPruned()
    {
        await using var host = await NoticeTestHost.CreateAsync(new NoticesOptions { RetentionDays = 1 });
        await host.IssuedAsync("a.contoso.local", validInDays: 400);
        host.Db.Notices.Add(new Notice
        {
            RequestId = Guid.NewGuid(), Kind = NoticeKind.RenewalStalled, Step = 1,
            CreatedAtUtc = host.Now.AddDays(-100), WebhookQueuedAtUtc = host.Now.AddDays(-100)
        });
        await host.Db.SaveChangesAsync(TestContext.Current.CancellationToken);

        var result = await host.SweepAsync();

        // The orphan resolves (its request does not exist) but is not deleted in the same pass.
        Assert.Equal(0, result.Pruned);
        Assert.Single(await host.NoticesAsync());
    }

    [Fact]
    public void TheSweepResult_PrintsAsASummary() =>
        Assert.Equal("resolved=1, raised=2, queued=3, pruned=4", new NoticeSweepResult(1, 2, 3, 4).ToString());
}
