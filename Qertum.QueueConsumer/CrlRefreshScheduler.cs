using System.Text.Json;
using Qertum.Services.Issuers;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;

namespace Qertum.QueueConsumer;

/// <summary>
/// Producer only: on a timer, queues a <see cref="WellKnownJobTypes.CrlRefresh"/> job when the
/// delta-CRL base is missing or old. Never publishes itself; <see cref="BackgroundJobProcessor"/> runs it.
/// </summary>
internal sealed class CrlRefreshScheduler(
    IServiceScopeFactory scopeFactory,
    IBackgroundJobSignal signal,
    IOptions<CrlRefreshOptions> options,
    ILogger<CrlRefreshScheduler> logger,
    TimeProvider clock,
    DistributedCacheMode cacheMode) : BackgroundService
{
    private readonly CrlRefreshOptions _options = options.Value;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_options.Enabled)
        {
            logger.LogInformation("Scheduled full-CRL refresh is disabled (CrlRefresh:Enabled = false).");
            return;
        }
        if (!cacheMode.IsShared)
        {
            logger.LogWarning(
                "Scheduled full-CRL refresh is off: no shared 'cache' connection string. A CRL published here would stay in this process's memory while the new delta base is recorded for every process. Configure Redis to enable it.");
            return;
        }

        var interval = TimeSpan.FromMinutes(_options.CheckIntervalMinutes);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAllAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Full-CRL refresh check failed; will retry in {Interval}.", interval);
            }

            try { await Task.Delay(interval, clock, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>The first job <see cref="CheckAllAsync"/> queued, or null.</summary>
    internal async Task<BackgroundJob?> CheckOnceAsync(CancellationToken cancellationToken) =>
        (await CheckAllAsync(cancellationToken)).FirstOrDefault();

    /// <summary>Queues a refresh for every issuer whose base is due. Returns the jobs queued.</summary>
    internal async Task<IReadOnlyList<BackgroundJob>> CheckAllAsync(CancellationToken cancellationToken)
    {
        // Without a shared cache the published CRL would stay private to this process while the
        // recorded base is shared, and ApiService would serve deltas citing a base nobody serves.
        if (!_options.Enabled || !cacheMode.IsShared) return [];

        await using var scope = scopeFactory.CreateAsyncScope();
        var registry = scope.ServiceProvider.GetRequiredService<IIssuerRegistry>();
        var crlState = scope.ServiceProvider.GetRequiredService<IssuerCrlState>();
        var queue = scope.ServiceProvider.GetRequiredService<IBackgroundJobQueue>();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        // AsNoTracking and no GetSettingsAsync: a read-only check must not create the settings row.
        var validityHours = await db.Settings.AsNoTracking().Select(s => s.CrlValidityHours).FirstOrDefaultAsync(cancellationToken);
        var now = clock.GetUtcNow().UtcDateTime;

        var candidates = await registry.GetCrlSigningHandlesAsync(cancellationToken);

        var queued = new List<BackgroundJob>();
        foreach (var handle in candidates)
        {
            var (_, baseThisUpdate) = await crlState.GetBaseAsync(handle.Issuer, cancellationToken);
            if (!CrlRefreshSchedule.IsDue(baseThisUpdate, validityHours, _options.RefreshAtFraction, now))
                continue;

            var job = await queue.EnqueueAsync(
                WellKnownJobTypes.CrlRefresh, CrlRefreshJobHandler.ConcurrencyKeyFor(handle.Issuer), CrlRefreshJobHandler.RequestedBy,
                CrlRefreshSchedule.Describe(baseThisUpdate, validityHours, _options.RefreshAtFraction, now),
                payloadJson: handle.Issuer.LegacyFiles ? null : JsonSerializer.Serialize(new { issuerId = handle.Issuer.Id }),
                cancellationToken: cancellationToken);
            if (job is not null) queued.Add(job);
        }

        if (queued.Count > 0) signal.TrySignal();
        return queued;
    }
}
