using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Recovery;

/// <summary>What the host's backup and restore scripts last reported, judged against the configured limits.</summary>
public interface IRecoveryStatusService
{
    /// <summary>Reads the thresholds from settings (without creating the row) and evaluates both records.</summary>
    Task<RecoveryStatus> GetAsync(CancellationToken cancellationToken = default);

    /// <summary>Evaluates both records against the given settings at <paramref name="nowUtc"/>. Reads two small files.</summary>
    RecoveryStatus Evaluate(CaSettings settings, DateTime nowUtc);
}

internal sealed class RecoveryStatusService(
    CertificateRequestDbContext db, SecretStorageOptions options, TimeProvider timeProvider) : IRecoveryStatusService
{
    public async Task<RecoveryStatus> GetAsync(CancellationToken cancellationToken = default)
    {
        // Read-only on purpose, like the attention report: ICertificateRequestService.GetSettingsAsync inserts the row.
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, cancellationToken)
                       ?? new CaSettings { Id = 1 };
        return Evaluate(settings, timeProvider.GetUtcNow().UtcDateTime);
    }

    public RecoveryStatus Evaluate(CaSettings settings, DateTime nowUtc) =>
        RecoveryRecords.Evaluate(options.DataDirectory, settings, nowUtc);
}
