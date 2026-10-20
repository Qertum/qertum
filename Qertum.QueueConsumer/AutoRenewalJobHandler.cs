using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Policies;

namespace Qertum.QueueConsumer;

/// <summary>
/// Runs <see cref="WellKnownJobTypes.AutoRenewal"/>: files an <c>auto-renewal</c> request for every
/// issued certificate inside the renewal window and, with <c>AutoRenewalAutoApprove</c>, approves it.
/// </summary>
internal sealed class AutoRenewalJobHandler(
    ICertificateRequestService service,
    ICertificateApprovalQueue approvalQueue,
    ILogger<AutoRenewalJobHandler> logger) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "auto-renewal";
    public const string RequestedBy = "auto-renewal-scheduler";
    public const string DisabledResult = "skipped: auto-renewal disabled";

    /// <summary>Same schedule as the timer it replaced: first scan 60 s after start, then every <c>CheckIntervalHours</c>.</summary>
    public static IntervalJob Schedule(AutoRenewalOptions options) => new(
        WellKnownJobTypes.AutoRenewal, ConcurrencyKey, RequestedBy,
        InitialDelay: TimeSpan.FromSeconds(60),
        Interval: TimeSpan.FromHours(options.CheckIntervalHours),
        // Read-only check: AsNoTracking, so a scheduler tick never creates the settings row.
        IsWanted: async (services, ct) => await services.GetRequiredService<CertificateRequestDbContext>().Settings
            .AsNoTracking().AnyAsync(s => s.AutoRenewalEnabled, ct));

    public string JobType => WellKnownJobTypes.AutoRenewal;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        // Re-read per run: the setting may have been switched off while the job waited.
        var settings = await service.GetSettingsAsync(cancellationToken);
        if (!settings.AutoRenewalEnabled)
            return DisabledResult;

        var daysBeforeExpiry = settings.AutoRenewalDaysBeforeExpiry ?? settings.ExpiringSoonDays;
        var certs = await service.GetCertsNeedingAutoRenewalAsync(daysBeforeExpiry, cancellationToken);

        if (certs.Count > 0)
            logger.LogInformation("Auto-renewal: {Count} certificate(s) need renewal (threshold: {Days} days).", certs.Count, daysBeforeExpiry);

        int renewed = 0, approved = 0, blocked = 0, failed = 0;
        foreach (var cert in certs)
        {
            try
            {
                var renewal = await service.RenewAsync(cert.Id, "auto-renewal", cancellationToken);
                if (renewal is null)
                {
                    logger.LogWarning("Auto-renewal: RenewAsync returned null for cert {Id} — skipping.", cert.Id);
                    failed++;
                    continue;
                }

                renewed++;
                logger.LogInformation("Auto-renewal: created renewal request {RenewalId} for cert {Id} ({CommonName}).",
                    renewal.Id, cert.Id, cert.CommonName);

                if (settings.AutoRenewalAutoApprove)
                {
                    try
                    {
                        var result = await service.MarkAsAutoApprovedAsync(
                            renewal.Id, "auto-renewal", "AutoRenewalAutoApprove", cancellationToken);
                        if (result is not null)
                        {
                            approved++;
                            approvalQueue.TrySignal();
                            logger.LogInformation("Auto-renewal: auto-approved renewal request {RenewalId}.", renewal.Id);
                        }
                    }
                    catch (IssuancePolicyViolationException ex)
                    {
                        // The renewal exists and stays Pending; GetCertsNeedingAutoRenewalAsync skips
                        // certificates with an active renewal, so this does not repeat every cycle.
                        blocked++;
                        logger.LogWarning(
                            "Auto-renewal: renewal request {RenewalId} left Pending; approval blocked by issuance policy. {Reason}",
                            renewal.Id, ex.Message);
                    }
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Per-certificate failures are skipped, not retried as a whole: the next scheduled
                // scan picks the certificate up again.
                failed++;
                logger.LogWarning(ex, "Auto-renewal: failed to renew cert {Id} ({CommonName}); skipping.", cert.Id, cert.CommonName);
            }
        }

        return string.Create(CultureInfo.InvariantCulture,
            $"due={certs.Count}, renewed={renewed}, approved={approved}, policyBlocked={blocked}, failed={failed} (threshold {daysBeforeExpiry} days)");
    }
}
