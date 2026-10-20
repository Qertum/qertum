using Microsoft.Extensions.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;

namespace Qertum.Tests.BackgroundJobs;

public sealed class CrlRefreshSchedulerTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CrlRefreshScheduler Scheduler(BackgroundJobTestHost host, CrlRefreshOptions? options = null, bool sharedCache = true) =>
        new(host.Services.GetRequiredService<IServiceScopeFactory>(), host.Services.GetRequiredService<IBackgroundJobSignal>(),
            Options.Create(options ?? new CrlRefreshOptions()), NullLogger<CrlRefreshScheduler>.Instance, host.Clock,
            new DistributedCacheMode(IsShared: sharedCache));

    private static async Task SeedBaseAsync(BackgroundJobTestHost host, DateTime? baseThisUpdateUtc, int validityHours = 24)
    {
        await using var db = host.Database.CreateContext();
        db.Settings.Add(new CaSettings { PqcStage = PqcStage.Off, Id = 1, CrlValidityHours = validityHours, BaseCrlNumber = 1, BaseCrlThisUpdateUtc = baseThisUpdateUtc });
        await db.SaveChangesAsync(Ct);
    }

    private static async Task<int> JobCountAsync(BackgroundJobTestHost host)
    {
        await using var db = host.Database.CreateContext();
        return await db.BackgroundJobs.CountAsync(Ct);
    }

    [Fact]
    public async Task CheckOnce_WhenTheBaseIsOldEnough_EnqueuesACrlRefresh_AndSignals()
    {
        await using var host = BackgroundJobTestHost.Create();
        await SeedBaseAsync(host, host.Clock.GetUtcNow().UtcDateTime.AddHours(-12));

        var job = await Scheduler(host).CheckOnceAsync(Ct);

        Assert.NotNull(job);
        Assert.Equal(WellKnownJobTypes.CrlRefresh, job!.JobType);
        Assert.Equal(CrlRefreshJobHandler.ConcurrencyKey, job.ConcurrencyKey);
        Assert.Equal(CrlRefreshJobHandler.RequestedBy, job.RequestedBy);
        Assert.Equal("base age 12.0 h >= 12.0 h", job.Reason);
        var signal = host.Services.GetRequiredService<IBackgroundJobSignal>();
        Assert.True(signal.WaitToReadAsync(Ct).IsCompleted);
    }

    [Fact]
    public async Task CheckOnce_WhenTheBaseIsFresh_EnqueuesNothing()
    {
        await using var host = BackgroundJobTestHost.Create();
        await SeedBaseAsync(host, host.Clock.GetUtcNow().UtcDateTime.AddHours(-11));

        Assert.Null(await Scheduler(host).CheckOnceAsync(Ct));
        Assert.Equal(0, await JobCountAsync(host));
    }

    [Fact]
    public async Task CheckOnce_WithAnUninitializedCa_EnqueuesNothing()
    {
        await using var host = BackgroundJobTestHost.Create(initializeCa: false);

        Assert.Null(await Scheduler(host).CheckOnceAsync(Ct));
        Assert.Equal(0, await JobCountAsync(host));
    }

    [Fact]
    public async Task CheckOnce_WhenDisabled_EnqueuesNothing()
    {
        await using var host = BackgroundJobTestHost.Create();

        Assert.Null(await Scheduler(host, new CrlRefreshOptions { Enabled = false }).CheckOnceAsync(Ct));
        Assert.Equal(0, await JobCountAsync(host));
    }

    // Without a shared cache the job's CRL would land in QueueConsumer's private memory while the
    // new base number lands in the shared database; ApiService would then serve deltas citing a
    // base no process serves.
    [Fact]
    public async Task CheckOnce_WithoutASharedCache_EnqueuesNothing()
    {
        await using var host = BackgroundJobTestHost.Create();

        Assert.Null(await Scheduler(host, sharedCache: false).CheckOnceAsync(Ct));
        Assert.Equal(0, await JobCountAsync(host));
    }

    [Fact]
    public async Task CheckOnce_WhileARefreshIsActive_DoesNotEnqueueASecond()
    {
        await using var host = BackgroundJobTestHost.Create();
        await SeedBaseAsync(host, null);
        var scheduler = Scheduler(host);

        Assert.NotNull(await scheduler.CheckOnceAsync(Ct));
        Assert.Null(await scheduler.CheckOnceAsync(Ct));
        Assert.Equal(1, await JobCountAsync(host));
    }

    [Fact]
    public async Task CheckOnce_WithNoSettingsRow_Enqueues()
    {
        await using var host = BackgroundJobTestHost.Create();

        var job = await Scheduler(host).CheckOnceAsync(Ct);

        Assert.NotNull(job);
        Assert.Equal("no base CRL published yet", job!.Reason);
    }
}
