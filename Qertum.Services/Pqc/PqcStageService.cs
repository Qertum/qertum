using Microsoft.EntityFrameworkCore;
using Qertum.Services.Lifecycle;
using Qertum.Services.Policies;

namespace Qertum.Services;

/// <summary>What the stage service needs to know about one request.</summary>
public sealed record PqcContext(
    string? TemplateTypeKey,
    CertificateKeyAlgorithm Algorithm,
    IReadOnlyList<string> DnsNames,
    bool HasNonDnsNames,
    bool IsRenewal,
    bool IsCaKey = false)
{
    /// <summary>Builds the context from a request: CN plus DNS SANs, and whether any other SAN kind is present.</summary>
    public static PqcContext FromRequest(CertificateRequest request, CertificateKeyAlgorithm algorithm, bool isRenewal)
    {
        var properties = IssuancePolicyEvaluator.ReadProperties(request.PropertiesJson);
        var names = new[] { request.CommonName }
            .Concat(properties.DnsNames)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        var nonDns = properties.IpAddresses.Count + properties.EmailAddresses.Count + properties.UserPrincipalNames.Count > 0;
        return new PqcContext(request.Type, algorithm, names, nonDns, isRenewal,
            IsCaKey: request.Type == WellKnownCertificateTypes.RootCa);
    }
}

/// <summary>Resolves the effective PQC stage and exceptions for a request and returns the verdict.</summary>
public interface IPqcStageService
{
    /// <summary>Evaluates without writing anything. Never throws for a refusal; callers decide.</summary>
    Task<PqcVerdict> EvaluateAsync(PqcContext context, CancellationToken cancellationToken = default);

    /// <summary>
    /// Records the verdict's diagnostic event against <paramref name="requestId"/> (a create has no id
    /// until the row exists). Non-fatal: failures are swallowed.
    /// </summary>
    void Record(PqcVerdict verdict, Guid requestId, string performedBy);

    /// <summary>
    /// Loads what a stage decision reads, once. <paramref name="stageOverride"/> replaces every template's
    /// stage (used by the migration report to judge a proposal). Read-only: never inserts the settings row.
    /// </summary>
    Task<PqcStageSnapshot> LoadSnapshotAsync(PqcStage? stageOverride = null, CancellationToken cancellationToken = default);

    /// <summary>As <see cref="EvaluateAsync(PqcContext, CancellationToken)"/>, judged under <paramref name="stageOverride"/> when it is not null.</summary>
    Task<PqcVerdict> EvaluateAsync(PqcContext context, PqcStage? stageOverride, CancellationToken cancellationToken = default);
}

/// <inheritdoc />
public sealed class PqcStageService(
    CertificateRequestDbContext db,
    IDiagnosticEventLog? diagnostics = null,
    TimeProvider? timeProvider = null) : IPqcStageService
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <inheritdoc />
    public async Task<PqcStageSnapshot> LoadSnapshotAsync(PqcStage? stageOverride = null, CancellationToken cancellationToken = default)
    {
        // Read-only on purpose: GetSettingsAsync inserts the singleton row.
        // No row means a CA that was never configured, which is the default stage.
        var defaultStage = await db.Settings.AsNoTracking().Where(s => s.Id == 1)
            .Select(s => (PqcStage?)s.PqcStage).FirstOrDefaultAsync(cancellationToken) ?? PqcStage.Enforce;

        var overrides = (await db.CertificateTemplates.AsNoTracking()
                .Select(t => new { t.TypeKey, t.PqcStageOverride }).ToListAsync(cancellationToken))
            .ToDictionary(t => t.TypeKey, t => t.PqcStageOverride, StringComparer.Ordinal);

        var now = _clock.GetUtcNow().UtcDateTime;
        var exceptions = await db.PqcExceptions.AsNoTracking()
            .Where(e => e.RevokedAtUtc == null && e.ExpiresAtUtc > now)
            .ToListAsync(cancellationToken);

        return new PqcStageSnapshot(defaultStage, overrides, exceptions, stageOverride, now);
    }

    /// <inheritdoc />
    public Task<PqcVerdict> EvaluateAsync(PqcContext context, CancellationToken cancellationToken = default) =>
        EvaluateAsync(context, stageOverride: null, cancellationToken);

    /// <inheritdoc />
    public async Task<PqcVerdict> EvaluateAsync(PqcContext context, PqcStage? stageOverride, CancellationToken cancellationToken = default) =>
        (await LoadSnapshotAsync(stageOverride, cancellationToken)).Evaluate(context).Verdict;

    /// <inheritdoc />
    public void Record(PqcVerdict verdict, Guid requestId, string performedBy)
    {
        if (verdict.EventAction is null || diagnostics is null) return;
        try
        {
            diagnostics.Record(LifecycleSubjectTypes.CertificateRequest, requestId, verdict.EventAction, performedBy,
                DiagnosticCategories.PqcStage, verdict.Reason);
        }
        catch
        {
            // A diagnostic can never fail issuance.
        }
    }
}
