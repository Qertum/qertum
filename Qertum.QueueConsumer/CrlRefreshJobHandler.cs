using System.Text.Json;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;
using Qertum.Services.Issuers;

namespace Qertum.QueueConsumer;

/// <summary>Runs <see cref="WellKnownJobTypes.CrlRefresh"/>: publishes a fresh full CRL and delta base for one issuer.</summary>
internal sealed class CrlRefreshJobHandler(IIssuerRegistry issuers, CrlPublisher publisher) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "crl-refresh";
    public const string RequestedBy = "crl-refresh-scheduler";
    public const string SkippedResult = "skipped: CA not initialized";

    /// <summary>The legacy issuer keeps the pre-hierarchy key; every other issuer gets its own.</summary>
    public static string ConcurrencyKeyFor(Issuer issuer) => issuer.LegacyFiles ? ConcurrencyKey : $"{ConcurrencyKey}:{issuer.Id}";

    public string JobType => WellKnownJobTypes.CrlRefresh;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        var handle = ReadIssuerId(job.PayloadJson) is { } id
            ? await issuers.GetAsync(id, cancellationToken)
            : await LegacyAsync(cancellationToken);
        // The scheduler checked this too; the job may have waited while the issuer changed state.
        if (handle is null) return SkippedResult;
        if (!handle.CanSignRevocation) return $"skipped: issuer {handle.Issuer.Name} is {handle.Issuer.Status}";

        var published = await publisher.PublishFullCrlAsync(handle, cancellationToken);
        return $"crlNumber={published.CrlNumber}";
    }

    /// <summary>
    /// A job with no payload is the legacy issuer's, even after another issuer became default — its
    /// key is <see cref="ConcurrencyKey"/> and its CRL is <c>/crl</c> for the CA it always was.
    /// </summary>
    private async Task<IssuerHandle?> LegacyAsync(CancellationToken ct)
    {
        var legacy = (await issuers.GetAllAsync(ct)).FirstOrDefault(i => i.LegacyFiles);
        return legacy is not null ? await issuers.GetAsync(legacy.Id, ct) : await issuers.GetDefaultAsync(ct);
    }

    private static IssuerId? ReadIssuerId(string? payload)
    {
        if (string.IsNullOrWhiteSpace(payload)) return null;
        using var doc = JsonDocument.Parse(payload);
        return doc.RootElement.TryGetProperty("issuerId", out var value) && value.TryGetGuid(out var guid) ? new IssuerId(guid) : null;
    }
}
