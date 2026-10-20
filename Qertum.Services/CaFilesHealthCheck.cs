using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Qertum.Services;

/// <summary>
/// Reports whether the CA signing backend is ready to issue.
///
/// Readiness is asked of <see cref="ICertificateGenerator.IsInitialized"/> rather than checked
/// here directly — that keeps this health check correct for whatever backend is configured
/// (today, <c>ca.key</c>/<c>ca.pem</c> on disk; a future Key Vault/HSM-backed
/// <c>ICaSigner</c> would report readiness by its own means, e.g. vault reachability, with no
/// change needed here).
///
/// A root CA request sitting <c>Pending</c>/<c>Approved</c>/<c>Processing</c> is expected,
/// possibly for a long time (approval is a manual step) — that state reports Healthy, not a
/// timer-based grace period. Unhealthy is reported only when the backend was configured
/// (<c>CaSettings</c> exists) and is not ready, with no root CA request in flight to explain
/// it — i.e. it was ready and now genuinely isn't (files removed, backend unreachable).
/// </summary>
public sealed class CaFilesHealthCheck(
    IServiceScopeFactory scopeFactory,
    ICertificateGenerator certificateGenerator,
    CaDataOptions caDataOptions,
    IMemoryCache cache,
    Issuers.IIssuerRegistry? issuers = null) : IHealthCheck
{
    private static readonly TimeSpan ResultCacheTtl = TimeSpan.FromSeconds(60);

    private const string ResultCacheKey = "health:ca-files:result";

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        if (cache.TryGetValue(ResultCacheKey, out HealthCheckResult cached))
            return cached;

        var result = await ComputeAsync(cancellationToken);
        // Only cache results that came from a successful DB query. Transient exceptions
        // (migration in progress, brief SQLite lock, startup race) must not be cached —
        // the next Aspire poll should retry rather than see a stale Unhealthy for 60 s.
        if (result.Exception is null)
            cache.Set(ResultCacheKey, result, ResultCacheTtl);
        return result;
    }

    private async Task<HealthCheckResult> ComputeAsync(CancellationToken cancellationToken)
    {
        bool onboardingDone;
        Guid? pendingRootCaId;
        bool? defaultCanIssue = null;
        var intermediatePending = false;
        try
        {
            await using var scope = scopeFactory.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var certificateRequestService = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
            onboardingDone = await db.Settings.AnyAsync(cancellationToken);
            pendingRootCaId = await certificateRequestService.GetPendingRootCaRequestIdAsync(cancellationToken);
            if (issuers is not null)
            {
                defaultCanIssue = (await issuers.GetDefaultAsync(cancellationToken))?.CanIssue == true;
                // An offline-root ceremony waiting for its signed intermediate is onboarding in progress too.
                intermediatePending = (await issuers.GetAllAsync(cancellationToken))
                    .Any(i => i.Status == IssuerStatus.PendingCertificate);
            }
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Could not query CA settings from the database.", ex);
        }

        if (!onboardingDone)
            return HealthCheckResult.Healthy("CA onboarding not yet completed.");

        if (defaultCanIssue ?? certificateGenerator.IsInitialized)
            return HealthCheckResult.Healthy();

        if (intermediatePending)
            return HealthCheckResult.Healthy("CA onboarding in progress — awaiting the signed intermediate certificate.");

        if (pendingRootCaId.HasValue)
            return HealthCheckResult.Healthy("CA onboarding in progress — awaiting root CA request approval/generation.");

        // Diagnostic detail on the files IsInitialized actually checked — this is what tells the
        // next occurrence apart from a directory mismatch between this process and whichever
        // process wrote the files (e.g. ApiService vs QueueConsumer resolving different absolute
        // paths for CaDataOptions.Directory, which should be impossible given they're both handed
        // the same connection-string-derived path, but this makes it visible instead of assumed).
        var keyPath = Path.Combine(caDataOptions.Directory, "ca.key");
        var pemPath = Path.Combine(caDataOptions.Directory, "ca.pem");
        return HealthCheckResult.Unhealthy(
            $"CA signing backend is not ready: CA is configured but not initialized, and no root CA request is in flight. " +
            $"Checked {caDataOptions.Directory}: ca.key exists={File.Exists(keyPath)}, ca.pem exists={File.Exists(pemPath)}.");
    }
}
