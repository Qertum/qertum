using Qertum.Services.Issuers;
using System.Data.Common;
using System.Diagnostics;
using Microsoft.Extensions.Caching.Distributed;
using System.Security.Cryptography;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Microsoft.Extensions.Logging.Abstractions;

namespace Qertum.QueueConsumer;

internal sealed class CertificateRequestQueueConsumer : BackgroundService
{
    private readonly IServiceScopeFactory serviceScopeFactory;
    private readonly ILogger<CertificateRequestQueueConsumer> logger;
    private readonly CertificateQueueMetrics metrics;
    private readonly OperationsMetrics? _operations;
    private readonly ICertificateApprovalQueue approvalQueue;
    private readonly ICertificateRevocationQueue revocationQueue;
    private readonly TimeSpan _idleDelay;
    private readonly TimeSpan _processingDelay;
    private readonly TimeSpan _failureDelay;

    public CertificateRequestQueueConsumer(
        IServiceScopeFactory serviceScopeFactory,
        ILogger<CertificateRequestQueueConsumer> logger,
        Microsoft.Extensions.Options.IOptions<QueueConsumerOptions> options,
        CertificateQueueMetrics metrics,
        ICertificateApprovalQueue approvalQueue,
        ICertificateRevocationQueue revocationQueue,
        OperationsMetrics? operations = null,
        TimeProvider? timeProvider = null)
    {
        _clock = timeProvider ?? TimeProvider.System;
        this.serviceScopeFactory = serviceScopeFactory;
        this.logger = logger;
        this.metrics = metrics;
        this.approvalQueue = approvalQueue;
        this.revocationQueue = revocationQueue;
        _operations = operations;
        _idleDelay = TimeSpan.FromMilliseconds(options.Value.IdleDelayMs);
        _processingDelay = TimeSpan.FromMilliseconds(options.Value.ProcessingDelayMs);
        _failureDelay = TimeSpan.FromMilliseconds(options.Value.ErrorDelayMs);
    }

    private readonly TimeProvider _clock;
    private const int MaxRetries = 3;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Recover any rows left in Processing state from a previous crash.
        // Don't block startup if this fails — the next dequeue cycle will retry.
        try
        {
            await using var startupScope = serviceScopeFactory.CreateAsyncScope();
            var svc = startupScope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
            var recovered = await svc.ResetStuckProcessingAsync(stoppingToken);
            if (recovered > 0)
                logger.LogWarning("Recovered {Count} stuck Processing request(s) to Approved on startup.", recovered);
        }
        catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Startup recovery of stuck Processing rows failed; will retry on next dequeue cycle.");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            await using var scope = serviceScopeFactory.CreateAsyncScope();
            var certificateRequestService = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();

            var didWork = false;

            // ── Issuance ──────────────────────────────────────────────────────────
            CertificateRequest? nextRequest;
            try
            {
                nextRequest = await certificateRequestService.DequeueNextApprovedAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            if (nextRequest is not null)
            {
                didWork = true;

                logger.LogInformation(
                    "Processing certificate request {CertificateRequestId} for {CommonName}",
                    nextRequest.Id,
                    nextRequest.CommonName);

                var sw = Stopwatch.StartNew();
                string? failureReason = null;
                var issued = false;
                var policyChecked = false;
                var policyRejected = false;

                for (var attempt = 0; attempt < MaxRetries && !stoppingToken.IsCancellationRequested; attempt++)
                {
                    if (attempt > 0)
                    {
                        var backoff = TimeSpan.FromSeconds(Math.Pow(2, attempt));
                        logger.LogWarning(
                            "Retrying certificate {CertificateRequestId} (attempt {Attempt}/{Max}) after {BackoffSeconds}s back-off.",
                            nextRequest.Id, attempt + 1, MaxRetries, backoff.TotalSeconds);
                        await Task.Delay(backoff, stoppingToken);
                    }

                    try
                    {
                        // Re-check the policy once per claim, before anything is signed: it may have
                        // tightened since approval. A failure while checking (e.g. a DbException) takes
                        // the normal retry path; only a completed violation stops issuance, and
                        // CheckIssuancePolicyAsync has already rejected the request with its reason.
                        if (!policyChecked)
                        {
                            var policyDecision = await certificateRequestService.CheckIssuancePolicyAsync(nextRequest.Id, stoppingToken);
                            policyChecked = true;
                            if (!policyDecision.Allowed)
                            {
                                logger.LogWarning(
                                    "Rejected certificate request {CertificateRequestId} before signing. {Reason}",
                                    nextRequest.Id, policyDecision.Summarize());
                                policyRejected = true;
                                break;
                            }
                        }

                        var settings = await certificateRequestService.GetSettingsAsync(stoppingToken);
                        var signer = scope.ServiceProvider.GetRequiredService<IssuanceSigner>();
                        var generatedCert = await signer.SignAsync(nextRequest, settings, stoppingToken);

                        if (nextRequest.Type == WellKnownCertificateTypes.RootCa)
                        {
                            // Sync CaSettings DN fields so leaf certs and the Settings page reflect the CA identity.
                            var issuers = scope.ServiceProvider.GetRequiredService<IIssuerRegistry>();
                            var caStatus = (await issuers.GetDefaultAsync(stoppingToken))?.Generator?.GetCaStatus() ?? new CaStatusResponse();
                            settings.OrganizationName = caStatus.OrganizationName;
                            settings.OrganizationalUnit = caStatus.OrganizationalUnit;
                            settings.Country = caStatus.Country;
                            settings.State = caStatus.State;
                            settings.Locality = caStatus.Locality;
                            await certificateRequestService.SetupOrUpdateSettingsAsync(settings, "queue-consumer", stoppingToken);
                        }

                        await Task.Delay(_processingDelay, stoppingToken);
                        await certificateRequestService.MarkAsIssuedAsync(
                            nextRequest.Id, generatedCert, "queue-consumer", stoppingToken);

                        sw.Stop();
                        var algorithm = nextRequest.KeyAlgorithm?.ToCanonicalString() ?? "Unknown";
                        var certType = nextRequest.Type ?? "Unknown";
                        metrics.IssueDuration.Record(
                            sw.Elapsed.TotalSeconds,
                            new KeyValuePair<string, object?>("algorithm", algorithm),
                            new KeyValuePair<string, object?>("certificate.type", certType));
                        metrics.IssuedTotal.Add(1,
                            new KeyValuePair<string, object?>("algorithm", algorithm),
                            new KeyValuePair<string, object?>("certificate.type", certType));

                        logger.LogInformation(
                            "Issued certificate {CertificateRequestId} for {CommonName} in {ElapsedMs:F0} ms",
                            nextRequest.Id,
                            nextRequest.CommonName,
                            sw.Elapsed.TotalMilliseconds);

                        issued = true;
                        break;
                    }
                    catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                    {
                        return;
                    }
                    catch (CryptographicException ex)
                    {
                        failureReason = $"CryptographicException on attempt {attempt + 1}: {ex.Message}";
                        logger.LogWarning(ex,
                            "Transient crypto error processing {CertificateRequestId} on attempt {Attempt}/{Max}.",
                            nextRequest.Id, attempt + 1, MaxRetries);
                    }
                    catch (DbException ex)
                    {
                        failureReason = $"DbException on attempt {attempt + 1}: {ex.Message}";
                        logger.LogWarning(ex,
                            "Transient DB error processing {CertificateRequestId} on attempt {Attempt}/{Max}.",
                            nextRequest.Id, attempt + 1, MaxRetries);
                    }
                    catch (Exception ex)
                    {
                        if (stoppingToken.IsCancellationRequested) return;
                        failureReason = $"Error on attempt {attempt + 1}: {ex.Message}";
                        logger.LogWarning(ex,
                            "Unexpected error processing {CertificateRequestId} on attempt {Attempt}/{Max}.",
                            nextRequest.Id, attempt + 1, MaxRetries);
                    }
                }

                if (!issued && !policyRejected && !stoppingToken.IsCancellationRequested)
                {
                    metrics.IssueErrors.Add(1,
                        new KeyValuePair<string, object?>("algorithm", nextRequest.KeyAlgorithm?.ToCanonicalString() ?? "Unknown"),
                        new KeyValuePair<string, object?>("certificate.type", nextRequest.Type ?? "Unknown"));
                    logger.LogError(
                        "Permanently rejecting {CertificateRequestId} after {Max} failed attempts. Reason: {FailureReason}",
                        nextRequest.Id, MaxRetries, failureReason);
                    try
                    {
                        await certificateRequestService.MarkAsRejectedWithReasonAsync(
                            nextRequest.Id, failureReason, "queue-consumer", stoppingToken);
                    }
                    catch (Exception rejectEx) when (!stoppingToken.IsCancellationRequested)
                    {
                        logger.LogError(rejectEx,
                            "Failed to reject stuck request {CertificateRequestId}.",
                            nextRequest.Id);
                        await Task.Delay(_failureDelay, stoppingToken);
                    }
                }
            }

            // ── Revocation ────────────────────────────────────────────────────────
            try
            {
                var revoked = await certificateRequestService.DequeueNextPendingRevocationAsync(stoppingToken);
                if (revoked is not null)
                {
                    didWork = true;
                    _operations?.Revocations.Add(1, new KeyValuePair<string, object?>("outcome", "revoked"));
                    logger.LogInformation(
                        "Revoked certificate request {CertificateRequestId} for {CommonName}",
                        revoked.Id,
                        revoked.CommonName);

                    // Drop the published CRL (and any cached delta, which is now relative to a base
                    // that no longer reflects this revocation) so the next request rebuilds a CRL
                    // that names this certificate. Waiting for either TTL instead would leave relying
                    // parties treating a revoked certificate as valid for up to CrlValidityHours.
                    var crlCache = scope.ServiceProvider.GetRequiredService<IDistributedCache>();
                    await EvictCrlOrQueueRefreshAsync(crlCache, scope.ServiceProvider.GetRequiredService<IIssuerRegistry>(),
                        scope.ServiceProvider, revoked, logger, stoppingToken);
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _operations?.Revocations.Add(1, new KeyValuePair<string, object?>("outcome", "error"));
                logger.LogError(ex, "Error processing pending revocation; will retry on next cycle.");
                await Task.Delay(_failureDelay, stoppingToken);
            }

            // ── Idle wait (no work found) ─────────────────────────────────────────
            if (!didWork)
            {
                using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                try
                {
                    // Include an explicit Task.Delay so the idle timeout is a real awaitable,
                    // not an implicit side-effect of token cancellation. Without it,
                    // Task.WhenAny returns as soon as either channel task resolves (which can
                    // happen before the timeout when the token is cancelled asynchronously).
                    await Task.WhenAny(
                        Task.Delay(_idleDelay, idleCts.Token),
                        approvalQueue.WaitToReadAsync(idleCts.Token).AsTask(),
                        revocationQueue.WaitToReadAsync(idleCts.Token).AsTask());
                }
                catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested) { }
                finally
                {
                    // Cancel the remaining channel waits so they unregister from the channel
                    // before the next iteration creates new ones.
                    await idleCts.CancelAsync();
                    approvalQueue.Drain();
                    revocationQueue.Drain();
                }
            }
        }
    }

    /// <summary>Drops the revoked row's issuer's cached full and delta CRL so the next fetch lists it.</summary>
    /// <summary>
    /// Drops the revoked row's issuer's cached full and delta CRL. True when both were dropped. Redis being
    /// down is not an exception here: it is logged and reported as false so the caller can queue a retry.
    /// </summary>
    internal static async Task<bool> EvictCrlAsync(IDistributedCache cache, IIssuerRegistry issuers, CertificateRequest revoked,
        CancellationToken ct, ILogger? logger = null)
    {
        logger ??= NullLogger.Instance;
        var issuer = (await issuers.ForRequestAsync(revoked, ct))?.Issuer;
        // Both are attempted even if the first fails: a dropped delta is still worth having.
        var full = await cache.TryRemoveAsync(issuer is null ? CrlCache.Key : CrlCache.KeyFor(issuer), logger, ct);
        var delta = await cache.TryRemoveAsync(issuer is null ? CrlCache.DeltaKey : CrlCache.DeltaKeyFor(issuer), logger, ct);
        return full && delta;
    }

    /// <summary>
    /// Evicts, and when the cache cannot be reached queues a <see cref="WellKnownJobTypes.CrlRefresh"/> job
    /// for the issuer. The row is already <c>Revoked</c> here, so this is the only retry the eviction gets:
    /// the job publishes a CRL that lists the revocation over whatever stale copy Redis still holds, and
    /// the job queue retries it with backoff until Redis answers.
    /// </summary>
    internal static async Task EvictCrlOrQueueRefreshAsync(IDistributedCache cache, IIssuerRegistry issuers,
        IServiceProvider services, CertificateRequest revoked, ILogger logger, CancellationToken ct)
    {
        if (await EvictCrlAsync(cache, issuers, revoked, ct, logger))
            return;

        // Resolved only now, so the eviction itself never depends on the job queue being available.
        var queue = services.GetRequiredService<IBackgroundJobQueue>();
        var signal = services.GetRequiredService<IBackgroundJobSignal>();

        var issuer = (await issuers.ForRequestAsync(revoked, ct))?.Issuer;
        var key = issuer is null ? CrlRefreshJobHandler.ConcurrencyKey : CrlRefreshJobHandler.ConcurrencyKeyFor(issuer);
        var payload = issuer is null || issuer.LegacyFiles ? null : System.Text.Json.JsonSerializer.Serialize(new { issuerId = issuer.Id });
        await queue.EnqueueAsync(WellKnownJobTypes.CrlRefresh, key, "revocation-eviction",
            "the cached CRL could not be dropped after a revocation", payloadJson: payload, cancellationToken: ct);
        signal.TrySignal();
        logger.LogWarning("Could not drop the cached CRL after revoking {CertificateRequestId}; queued a CRL refresh ({Key}).",
            revoked.Id, key);
    }
}
