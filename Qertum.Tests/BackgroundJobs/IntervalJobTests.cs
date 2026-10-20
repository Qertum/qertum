using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.BackgroundJobs;

/// <summary>
/// The former timer services (auto-renewal, lifecycle-event retention, ACME expiry cleanup) run as
/// scheduled background jobs: each run is queued, claimed and completed with its diagnostic events.
/// </summary>
public sealed class IntervalJobTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static BackgroundJobTestHost NewHost() => BackgroundJobTestHost.Create(configure: s =>
    {
        s.AddSingleton<ICertificateApprovalQueue, CertificateApprovalChannel>();
        s.AddScoped<IBackgroundJobHandler, AutoRenewalJobHandler>();
    });

    private static IntervalJobScheduler Scheduler(BackgroundJobTestHost host, IntervalJob schedule) =>
        new(schedule, host.Services.GetRequiredService<IServiceScopeFactory>(),
            host.Services.GetRequiredService<IBackgroundJobSignal>(), NullLogger<IntervalJobScheduler>.Instance, host.Clock);

    private static BackgroundJobProcessor Processor(BackgroundJobTestHost host) =>
        new(host.Services.GetRequiredService<IServiceScopeFactory>(), host.Services.GetRequiredService<IBackgroundJobSignal>(),
            Options.Create(new BackgroundJobOptions()), NullLogger<BackgroundJobProcessor>.Instance, host.Clock);

    private static IntervalJob AutoRenewal => AutoRenewalJobHandler.Schedule(new AutoRenewalOptions());

    private static async Task SeedAsync(BackgroundJobTestHost host, bool autoRenewalEnabled, params CertificateRequest[] requests)
    {
        await using var db = host.Database.CreateContext();
        db.Settings.Add(new CaSettings { PqcStage = PqcStage.Off, Id = 1, AutoRenewalEnabled = autoRenewalEnabled, AutoRenewalDaysBeforeExpiry = 30 });
        db.CertificateRequests.AddRange(requests);
        await db.SaveChangesAsync(Ct);
    }

    private static CertificateRequest IssuedExpiringIn(BackgroundJobTestHost host, string commonName, int days)
    {
        var now = host.Clock.GetUtcNow().UtcDateTime;
        return new CertificateRequest
        {
            CommonName = commonName,
            Type = "WebServer",
            RequestedBy = "alice",
            RequestedBySubject = "alice-sub",
            Status = CertificateRequestStatus.Issued,
            CertificatePem = "pem",
            ValidFrom = now.AddDays(-300),
            ValidTo = now.AddDays(days)
        };
    }

    [Fact]
    public async Task Scheduler_QueuesOneJobUnderItsKey_AndAnActiveOneAbsorbsTheNextTick()
    {
        await using var host = NewHost();
        await SeedAsync(host, autoRenewalEnabled: true);
        var scheduler = Scheduler(host, AutoRenewal);

        var job = await scheduler.EnqueueOnceAsync(Ct);

        Assert.NotNull(job);
        Assert.Equal(WellKnownJobTypes.AutoRenewal, job!.JobType);
        Assert.Equal(AutoRenewalJobHandler.ConcurrencyKey, job.ConcurrencyKey);
        Assert.Equal(AutoRenewalJobHandler.RequestedBy, job.RequestedBy);
        Assert.True(host.Services.GetRequiredService<IBackgroundJobSignal>().WaitToReadAsync(Ct).IsCompleted);
        Assert.Null(await scheduler.EnqueueOnceAsync(Ct));
    }

    [Fact]
    public async Task AutoRenewalScheduler_WhenDisabled_QueuesNothing_AndNeverCreatesTheSettingsRow()
    {
        await using var host = NewHost();

        Assert.Null(await Scheduler(host, AutoRenewal).EnqueueOnceAsync(Ct));

        Assert.Null(await host.SettingsAsync());
        await using var db = host.Database.CreateContext();
        Assert.Equal(0, await db.BackgroundJobs.CountAsync(Ct));
    }

    [Fact]
    public async Task DisabledSchedule_QueuesNothing()
    {
        await using var host = NewHost();
        var schedule = AcmeExpiryCleanupJobHandler.Schedule(new AcmeExpiryCleanupOptions { Enabled = false });

        Assert.Null(await Scheduler(host, schedule).EnqueueOnceAsync(Ct));
    }

    [Fact]
    public async Task AutoRenewalJob_RenewsDueCertificates_RecordsEveryStep_AndTheNextRunFindsNothingNew()
    {
        await using var host = NewHost();
        var due = IssuedExpiringIn(host, "due.contoso.local", 10);
        await SeedAsync(host, autoRenewalEnabled: true, due, IssuedExpiringIn(host, "later.contoso.local", 200));
        var scheduler = Scheduler(host, AutoRenewal);
        var processor = Processor(host);

        var job = await scheduler.EnqueueOnceAsync(Ct);
        Assert.True(await processor.RunOnceAsync(Ct));

        var actions = host.Diagnostics.Entries.Where(e => e.SubjectId == job!.Id.Value).Select(e => e.Action).ToList();
        Assert.Equal([DiagnosticActions.JobQueued, DiagnosticActions.JobClaimed, DiagnosticActions.JobCompleted], actions);
        Assert.StartsWith("due=1, renewed=1, approved=0",
            host.Diagnostics.Entries.Single(e => e.Action == DiagnosticActions.JobCompleted).Detail);

        await using (var db = host.Database.CreateContext())
        {
            var renewal = await db.CertificateRequests.SingleAsync(r => r.RenewedFromId == due.Id, Ct);
            Assert.Equal(CertificateRequestStatus.Pending, renewal.Status);
        }

        // The active-renewal skip is what stops a new Pending row every interval.
        host.Clock.Advance(TimeSpan.FromHours(24));
        await scheduler.EnqueueOnceAsync(Ct);
        Assert.True(await processor.RunOnceAsync(Ct));
        Assert.StartsWith("due=0, renewed=0",
            host.Diagnostics.Entries.Last(e => e.Action == DiagnosticActions.JobCompleted).Detail);
        await using var check = host.Database.CreateContext();
        Assert.Equal(1, await check.CertificateRequests.CountAsync(r => r.RenewedFromId == due.Id, Ct));
    }

    [Fact]
    public async Task AutoRenewalJob_SwitchedOffWhileQueued_Skips()
    {
        await using var host = NewHost();
        await SeedAsync(host, autoRenewalEnabled: true, IssuedExpiringIn(host, "due.contoso.local", 10));
        await Scheduler(host, AutoRenewal).EnqueueOnceAsync(Ct);
        await using (var db = host.Database.CreateContext())
        {
            await db.Settings.ExecuteUpdateAsync(s => s.SetProperty(x => x.AutoRenewalEnabled, false), Ct);
        }

        Assert.True(await Processor(host).RunOnceAsync(Ct));

        Assert.Equal(AutoRenewalJobHandler.DisabledResult,
            host.Diagnostics.Entries.Single(e => e.Action == DiagnosticActions.JobCompleted).Detail);
    }

    [Fact]
    public async Task Schedules_KeepTheTimersTheyReplaced()
    {
        var renewal = AutoRenewalJobHandler.Schedule(new AutoRenewalOptions { CheckIntervalHours = 6 });
        Assert.Equal((TimeSpan.FromSeconds(60), TimeSpan.FromHours(6)), (renewal.InitialDelay, renewal.Interval));

        var retention = LifecycleEventRetentionJobHandler.Schedule;
        Assert.Equal((TimeSpan.Zero, TimeSpan.FromDays(1)), (retention.InitialDelay, retention.Interval));

        var cleanup = AcmeExpiryCleanupJobHandler.Schedule(new AcmeExpiryCleanupOptions());
        Assert.Equal((TimeSpan.Zero, TimeSpan.FromHours(1)), (cleanup.InitialDelay, cleanup.Interval));
    }

    [Fact]
    public void QueueConsumerRegistration_SchedulesEveryIntervalJob_AndHasAHandlerForEach()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().Build());
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IBackgroundJobSignal, BackgroundJobChannel>();
        services.AddQueueConsumerOptions();
        services.AddBackgroundJobs();
        using var provider = services.BuildServiceProvider();

        // Only the factory registrations: resolving every hosted service would need the whole host.
        var scheduled = services
            .Where(d => d.ServiceType == typeof(IHostedService) && d.ImplementationFactory is not null)
            .Select(d => d.ImplementationFactory!(provider)).OfType<IntervalJobScheduler>()
            .Select(s => s.Schedule.JobType).Order().ToList();
        Assert.Equal(
            [WellKnownJobTypes.AcmeExpiryCleanup, WellKnownJobTypes.ApprovalRetention, WellKnownJobTypes.AuditCheckpoint, WellKnownJobTypes.AutoRenewal, WellKnownJobTypes.BulkOperationRetention, WellKnownJobTypes.LifecycleEventRetention, WellKnownJobTypes.Notices],
            scheduled);

        var handled = services.Where(d => d.ServiceType == typeof(IBackgroundJobHandler))
            .Select(d => d.ImplementationType!.Name).ToList();
        Assert.Equal(
            [nameof(CrlRefreshJobHandler), nameof(AutoRenewalJobHandler), nameof(LifecycleEventRetentionJobHandler), nameof(AcmeExpiryCleanupJobHandler),
             nameof(BulkOperationJobHandler), nameof(BulkOperationRetentionJobHandler), nameof(ApprovalRetentionJobHandler), nameof(NoticeJobHandler), nameof(AuditCheckpointJobHandler)],
            handled);
    }
}
