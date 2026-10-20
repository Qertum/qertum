using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qertum.Services.Lifecycle;

namespace Qertum.Services;

/// <summary>What the caller may see of the report. Resolved in the endpoint handler: permission policies need <c>HttpContext</c> as the resource.</summary>
/// <param name="CanViewObserved">The caller holds <c>settings.edit</c>, which guards diagnostic events.</param>
public sealed record PqcReportAccess(bool CanViewObserved);

/// <summary>Builds the PQC migration report. Read-only.</summary>
public interface IPqcMigrationReportService
{
    /// <summary>
    /// Computes the report on demand from live tables. Throws <see cref="NotFoundException"/> for an unknown
    /// <see cref="PqcReportQuery.TemplateTypeKey"/> and <see cref="ArgumentException"/> for a query that fails
    /// <see cref="PqcReportQuery.Validate"/>. Writes no row, audit entry, diagnostic event or webhook.
    /// </summary>
    Task<PqcMigrationReportResponse> BuildAsync(PqcReportQuery query, PqcReportAccess access, CancellationToken cancellationToken = default);
}

/// <inheritdoc />
public sealed class PqcMigrationReportService(
    CertificateRequestDbContext db,
    IPqcStageService stages,
    CertificateInventoryService inventory,
    IOptions<LifecycleEventsOptions> lifecycle,
    TimeProvider? timeProvider = null) : IPqcMigrationReportService
{
    private const string NoTemplateName = "(no template)";

    private static readonly string[] StageEventActions =
        [PqcEventActions.Observed, PqcEventActions.Warned, PqcEventActions.ExceptionApplied];

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly LifecycleEventsOptions _lifecycle = lifecycle.Value;

    // Only the columns a verdict needs: no PEM, no key material.
    private sealed record Row(CertificateRequestId Id, string CommonName, string Type, CertificateKeyAlgorithm? KeyAlgorithm,
        string PropertiesJson, CertificateRequestId? RenewedFromId, DateTime? ValidTo, CertificateRequestStatus Status);

    private sealed record Judged(Row Row, CertificateKeyAlgorithm Algorithm, bool Assumed, bool Compliant, bool IsRenewal,
        bool InFlight, PqcVerdictKind Kind, PqcEvaluation Evaluation);

    /// <inheritdoc />
    public async Task<PqcMigrationReportResponse> BuildAsync(PqcReportQuery query, PqcReportAccess access,
        CancellationToken cancellationToken = default)
    {
        if (query.Validate() is { } invalid) throw new ArgumentException(invalid, nameof(query));

        var now = _clock.GetUtcNow().UtcDateTime;
        var templates = await db.CertificateTemplates.AsNoTracking()
            .Select(t => new { t.TypeKey, t.Name }).ToListAsync(cancellationToken);
        // The report lists request types with no template (root CA, deleted templates), so those must be filterable too.
        if (query.TemplateTypeKey is { } wanted && templates.All(t => t.TypeKey != wanted)
            && !await db.CertificateRequests.AsNoTracking().AnyAsync(r => r.Type == wanted, cancellationToken))
            throw new NotFoundException($"Template '{wanted}' does not exist.");

        var snapshot = await stages.LoadSnapshotAsync(query.ProposedStage, cancellationToken);

        var scoped = db.CertificateRequests.AsNoTracking()
            .Where(r => query.TemplateTypeKey == null || r.Type == query.TemplateTypeKey);
        var live = await ProjectAsync(scoped.Where(r => r.Status == CertificateRequestStatus.Issued && r.ValidTo > now), cancellationToken);
        var inFlight = await ProjectAsync(scoped.Where(r => r.Status == CertificateRequestStatus.Pending
                                                            || r.Status == CertificateRequestStatus.Approved), cancellationToken);
        var notAffected = (await scoped
                .Where(r => (r.Status == CertificateRequestStatus.Issued && !(r.ValidTo > now))
                            || r.Status == CertificateRequestStatus.PendingRevocation
                            || r.Status == CertificateRequestStatus.Revoked)
                .GroupBy(r => r.Type ?? "").Select(g => new { Type = g.Key, Count = g.Count() })
                .ToListAsync(cancellationToken))
            .ToDictionary(g => g.Type, g => g.Count, StringComparer.Ordinal);

        // A live certificate is judged as RenewAsync judges it; an in-flight request as approval does.
        var judgedLive = live.Select(r => Judge(snapshot, r, isRenewal: true, inFlight: false)).ToList();
        var judgedInFlight = inFlight.Select(r => Judge(snapshot, r, isRenewal: r.RenewedFromId is not null, inFlight: true)).ToList();

        var reports = BuildTemplateReports(templates.Select(t => (t.TypeKey, t.Name)), query, snapshot, judgedLive, judgedInFlight, notAffected);
        var items = await PageItemsAsync(judgedLive.Concat(judgedInFlight), query, cancellationToken);

        return new PqcMigrationReportResponse
        {
            GeneratedAtUtc = now,
            CaDefaultStage = snapshot.DefaultStage,
            ProposedStage = query.ProposedStage,
            Templates = reports,
            Items = items,
            Observed = access.CanViewObserved ? await BuildObservedAsync(query, now, cancellationToken) : null,
            Withheld = access.CanViewObserved ? [] : ["observed"]
        };
    }

    private async Task<PqcObservedTraffic> BuildObservedAsync(PqcReportQuery query, DateTime now, CancellationToken ct)
    {
        // Never claim more history than exists: diagnostic rows are deleted after the retention.
        var retention = Math.Max(1, _lifecycle.DiagnosticRetentionDays);
        var effective = Math.Min(query.ObservedDays, retention);
        var since = now.AddDays(-effective);

        var grouped = await db.LifecycleEvents.AsNoTracking()
            .Where(e => e.Kind == LifecycleEventKinds.Diagnostic
                        && e.SubjectType == LifecycleSubjectTypes.CertificateRequest
                        && StageEventActions.Contains(e.Action)
                        && e.OccurredAtUtc >= since)
            .GroupBy(e => new { e.SubjectId, e.Action, e.PerformedBy })
            .Select(g => new { g.Key.SubjectId, g.Key.Action, g.Key.PerformedBy, Count = g.Count() })
            .ToListAsync(ct);

        // Which template and source each event belongs to comes from its request row, which may be gone.
        var owners = new Dictionary<Guid, (string Type, string? Subject)>();
        foreach (var chunk in grouped.Select(g => g.SubjectId).Distinct().Chunk(500))
        {
            var ids = chunk.Select(id => new CertificateRequestId(id)).ToList();
            foreach (var row in await db.CertificateRequests.AsNoTracking().Where(r => ids.Contains(r.Id))
                         .Select(r => new { r.Id, Type = r.Type ?? "", r.RequestedBySubject }).ToListAsync(ct))
                owners[row.Id] = (row.Type, row.RequestedBySubject);
        }

        var attributed = grouped
            .Select(g => owners.TryGetValue(g.SubjectId, out var owner)
                ? (Template: owner.Type, Source: SourceOf(owner.Subject), g.Action, g.PerformedBy, g.Count)
                : (Template: "unknown", Source: "unknown", g.Action, g.PerformedBy, g.Count))
            // A template filter can only be honoured for events that can be attributed to a template.
            .Where(e => query.TemplateTypeKey is null || e.Template == query.TemplateTypeKey)
            .ToList();

        return new PqcObservedTraffic
        {
            RequestedDays = query.ObservedDays,
            EffectiveDays = effective,
            RetentionDays = retention,
            SinceUtc = since,
            TotalEvents = attributed.Sum(e => e.Count),
            DistinctIdentities = attributed.Select(e => e.PerformedBy).Distinct(StringComparer.Ordinal).Count(),
            Counts = [.. attributed
                .GroupBy(e => (e.Template, e.Source, Kind: KindOf(e.Action)))
                .OrderBy(g => g.Key.Template, StringComparer.Ordinal).ThenBy(g => g.Key.Source, StringComparer.Ordinal)
                .ThenBy(g => g.Key.Kind, StringComparer.Ordinal)
                .Select(g => new PqcObservedCount
                {
                    TemplateTypeKey = g.Key.Template, Source = g.Key.Source, Kind = g.Key.Kind,
                    Count = g.Sum(e => e.Count),
                    DistinctIdentities = g.Select(e => e.PerformedBy).Distinct(StringComparer.Ordinal).Count()
                })]
        };
    }

    /// <summary>Where a request came from, by the owner prefix the protocols stamp on <c>RequestedBySubject</c>.</summary>
    private static string SourceOf(string? subject) => subject switch
    {
        not null when subject.StartsWith("acme:", StringComparison.Ordinal) => "acme",
        not null when subject.StartsWith("est-cert:", StringComparison.Ordinal) => "est-cert",
        not null when subject.StartsWith("est:", StringComparison.Ordinal) => "est",
        _ => "rest"
    };

    private static string KindOf(string action) => action switch
    {
        PqcEventActions.Observed => "Observed",
        PqcEventActions.Warned => "Warned",
        _ => "ExceptionApplied"
    };

    private static async Task<List<Row>> ProjectAsync(IQueryable<CertificateRequest> source, CancellationToken ct) =>
        await source.Select(r => new Row(r.Id, r.CommonName, r.Type ?? "", r.KeyAlgorithm, r.PropertiesJson ?? "{}", r.RenewedFromId, r.ValidTo, r.Status))
            .ToListAsync(ct);

    private static Judged Judge(PqcStageSnapshot snapshot, Row row, bool isRenewal, bool inFlight)
    {
        // A null stored algorithm is what RenewAsync assumes RSA for; a preview must not disagree with the action.
        var algorithm = row.KeyAlgorithm ?? CertificateKeyAlgorithm.Rsa;
        var shim = new CertificateRequest { CommonName = row.CommonName, Type = row.Type, PropertiesJson = row.PropertiesJson };
        var evaluation = snapshot.Evaluate(PqcContext.FromRequest(shim, algorithm, isRenewal));
        var compliant = PqcStageEvaluator.IsCompliant(algorithm);
        var kind = evaluation.Verdict switch
        {
            { Outcome: PqcOutcome.Refused } => PqcVerdictKind.Refused,
            { EventAction: PqcEventActions.ExceptionApplied } => PqcVerdictKind.CoveredByException,
            { Outcome: PqcOutcome.AllowedWithWarning } => PqcVerdictKind.Warned,
            _ => PqcVerdictKind.Allowed
        };
        return new Judged(row, algorithm, row.KeyAlgorithm is null, compliant, isRenewal, inFlight, kind, evaluation);
    }

    private static List<PqcTemplateReport> BuildTemplateReports(IEnumerable<(string TypeKey, string Name)> templates,
        PqcReportQuery query, PqcStageSnapshot snapshot, List<Judged> live, List<Judged> inFlight,
        IReadOnlyDictionary<string, int> notAffected)
    {
        var names = templates.ToDictionary(t => t.TypeKey, t => t.Name, StringComparer.Ordinal);
        // Templates in scope, plus any request type that has no template (root CA requests, deleted templates).
        var keys = names.Keys
            .Where(k => query.TemplateTypeKey is null || k == query.TemplateTypeKey)
            .Concat(live.Select(j => j.Row.Type)).Concat(inFlight.Select(j => j.Row.Type)).Concat(notAffected.Keys)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToList();

        return [.. keys.Select(key =>
        {
            var isCaType = key == WellKnownCertificateTypes.RootCa;
            var mine = live.Where(j => j.Row.Type == key).ToList();
            return new PqcTemplateReport
            {
                TypeKey = key,
                Name = names.GetValueOrDefault(key, NoTemplateName),
                CurrentStage = snapshot.CurrentStageFor(key, isCaType),
                ProposedStage = snapshot.EffectiveStageFor(key, isCaType),
                LiveTotal = mine.Count,
                Compliant = mine.Count(j => j.Compliant),
                ClassicalAllowed = mine.Count(j => !j.Compliant && j.Kind == PqcVerdictKind.Allowed),
                ClassicalWarned = mine.Count(j => !j.Compliant && j.Kind == PqcVerdictKind.Warned),
                ClassicalRefused = mine.Count(j => !j.Compliant && j.Kind == PqcVerdictKind.Refused),
                ClassicalCoveredByException = mine.Count(j => !j.Compliant && j.Kind == PqcVerdictKind.CoveredByException),
                AlgorithmAssumed = mine.Count(j => j.Assumed),
                InFlight = inFlight.Count(j => j.Row.Type == key),
                NotAffected = notAffected.GetValueOrDefault(key)
            };
        })];
    }

    private async Task<PagedResult<PqcReportItem>> PageItemsAsync(IEnumerable<Judged> judged, PqcReportQuery query, CancellationToken ct)
    {
        // Every classical row is a remaining dependency, whatever the stage would do with it; a compliant key is counted, not listed.
        var classical = judged.Where(j => !j.Compliant)
            .OrderBy(j => KindRank(j.Kind)).ThenBy(j => j.Row.ValidTo ?? DateTime.MaxValue).ThenBy(j => (Guid)j.Row.Id)
            .ToList();
        var page = classical.Skip((int)Math.Min((long)(query.Page - 1) * query.PageSize, int.MaxValue)).Take(query.PageSize).ToList();

        // PEM is parsed for the returned page only.
        var facts = (await inventory.GetForRequestsAsync([.. page.Select(j => j.Row.Id)], ct))
            .ToLookup(f => f.RequestId);

        return new PagedResult<PqcReportItem>
        {
            Items = [.. page.Select(j => new PqcReportItem
            {
                RequestId = j.Row.Id,
                CommonName = j.Row.CommonName,
                TemplateTypeKey = j.Row.Type,
                ValidToUtc = j.Row.ValidTo,
                Status = j.Row.Status,
                KeyAlgorithm = j.Algorithm.ToCanonicalString(),
                AlgorithmAssumed = j.Assumed,
                Verdict = j.Kind,
                Reason = j.Evaluation.Verdict.Reason,
                ExceptionId = j.Evaluation.ExceptionId,
                IsRenewal = j.IsRenewal,
                InFlight = j.InFlight,
                Certificates = [.. facts[j.Row.Id]]
            })],
            TotalCount = classical.Count,
            Page = query.Page,
            PageSize = query.PageSize
        };
    }

    private static int KindRank(PqcVerdictKind kind) => kind switch
    {
        PqcVerdictKind.Refused => 0,
        PqcVerdictKind.CoveredByException => 1,
        PqcVerdictKind.Warned => 2,
        _ => 3
    };
}
