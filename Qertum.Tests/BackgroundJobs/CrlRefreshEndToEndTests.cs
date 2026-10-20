using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.BackgroundJobs;

/// <summary>
/// The problem this closes: a deployment whose clients only fetch <c>/crl/delta</c> never published
/// a new full CRL, so the delta base's own NextUpdate lapsed.
/// </summary>
public sealed class CrlRefreshEndToEndTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static (CrlRefreshScheduler Scheduler, BackgroundJobProcessor Processor) Wire(BackgroundJobTestHost host)
    {
        var scopes = host.Services.GetRequiredService<IServiceScopeFactory>();
        var signal = host.Services.GetRequiredService<IBackgroundJobSignal>();
        return (
            new CrlRefreshScheduler(scopes, signal, Options.Create(new CrlRefreshOptions()), NullLogger<CrlRefreshScheduler>.Instance, host.Clock, new DistributedCacheMode(IsShared: true)),
            new BackgroundJobProcessor(scopes, signal, Options.Create(new BackgroundJobOptions()), NullLogger<BackgroundJobProcessor>.Instance, host.Clock));
    }

    private static BackgroundJobTestHost NewHost() =>
        BackgroundJobTestHost.Create(configure: s => s.AddScoped<IBackgroundJobHandler, CrlRefreshJobHandler>());

    [Fact]
    public async Task AScheduledRefresh_PublishesANewBase_EvictsTheDelta_AndRecordsEveryStep()
    {
        await using var host = NewHost();
        var (scheduler, processor) = Wire(host);
        var cache = host.Services.GetRequiredService<IDistributedCache>();
        await cache.SetAsync(CrlCache.DeltaKey, [1, 2, 3], Ct);

        var job = await scheduler.CheckOnceAsync(Ct);
        Assert.True(await processor.RunOnceAsync(Ct));

        var settings = await host.SettingsAsync();
        Assert.Equal(host.Clock.GetUtcNow().UtcDateTime, settings!.BaseCrlThisUpdateUtc);
        Assert.Null(await cache.GetAsync(CrlCache.DeltaKey, Ct));
        Assert.NotNull(await cache.GetAsync(CrlCache.Key, Ct));
        var actions = host.Diagnostics.Entries.Where(e => e.SubjectId == job!.Id.Value).Select(e => e.Action).ToList();
        Assert.Equal([DiagnosticActions.JobQueued, DiagnosticActions.JobClaimed, DiagnosticActions.JobCompleted], actions);
        Assert.Equal($"crlNumber={settings.BaseCrlNumber}",
            host.Diagnostics.Entries.Single(e => e.Action == DiagnosticActions.JobCompleted).Detail);
    }

    [Fact]
    public async Task WithOnlyDeltaFetches_TheBaseNeverLapsesOverThreeDays()
    {
        await using var host = NewHost();
        var (scheduler, processor) = Wire(host);
        var end = host.Clock.GetUtcNow().AddDays(3);

        while (host.Clock.GetUtcNow() < end)
        {
            await scheduler.CheckOnceAsync(Ct);
            while (await processor.RunOnceAsync(Ct)) { }

            var settings = await host.SettingsAsync();
            var baseNextUpdate = settings!.BaseCrlThisUpdateUtc!.Value.AddHours(CrlPublisher.EffectiveValidityHours(settings.CrlValidityHours));
            Assert.True(baseNextUpdate > host.Clock.GetUtcNow().UtcDateTime,
                $"Base CRL lapsed at {host.Clock.GetUtcNow():O} (base {settings.BaseCrlThisUpdateUtc:O}).");

            host.Clock.Advance(TimeSpan.FromMinutes(15));
        }

        // About one refresh per 12 hours over three days, not one per tick.
        var published = host.Diagnostics.Entries.Count(e => e.Action == DiagnosticActions.JobCompleted);
        Assert.InRange(published, 6, 8);
    }

    [Fact]
    public async Task TheHandler_WithAnUninitializedCa_CompletesAsSkipped()
    {
        await using var host = BackgroundJobTestHost.Create(initializeCa: false,
            configure: s => s.AddScoped<IBackgroundJobHandler, CrlRefreshJobHandler>());
        await using var scope = host.Services.CreateAsyncScope();
        var handler = scope.ServiceProvider.GetRequiredService<IBackgroundJobHandler>();

        Assert.Equal(CrlRefreshJobHandler.SkippedResult, await handler.HandleAsync(new BackgroundJob { JobType = WellKnownJobTypes.CrlRefresh }, Ct));
    }
}
