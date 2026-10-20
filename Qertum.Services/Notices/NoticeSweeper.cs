using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace Qertum.Services.Notices;

/// <summary>What one sweep did, for the job's result line.</summary>
/// <param name="Resolved">Open notices closed because their situation ended.</param>
/// <param name="Raised">New notices inserted.</param>
/// <param name="Queued">Webhooks queued, including retries of earlier lost deliveries.</param>
/// <param name="Pruned">Resolved notices deleted past their retention.</param>
public readonly record struct NoticeSweepResult(int Resolved, int Raised, int Queued, int Pruned)
{
    /// <inheritdoc />
    public override string ToString() => string.Create(CultureInfo.InvariantCulture,
        $"resolved={Resolved}, raised={Raised}, queued={Queued}, pruned={Pruned}");
}

/// <summary>
/// Keeps the Notices table true: closes notices whose situation ended, raises the due ones (once per step),
/// queues their webhooks at least once, and prunes old resolved rows. Safe to repeat after a crash: the unique
/// index refuses a second row for a step, and a row whose webhook was never queued is queued on the next sweep.
/// </summary>
public sealed class NoticeSweeper(
    CertificateRequestDbContext db,
    IAuditLogService auditLog,
    IWebhookService webhooks,
    IOptions<NoticesOptions> options,
    TimeProvider? timeProvider = null)
{
    private const string Actor = "notices-scheduler";

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <summary>Runs one sweep: resolve, raise, deliver, prune.</summary>
    public async Task<NoticeSweepResult> RunAsync(CancellationToken cancellationToken = default)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var opts = options.Value;
        // Read-only, so a sweep never creates the settings row.
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, cancellationToken)
                       ?? new CaSettings { Id = 1 };

        var resolved = await ResolveAsync(now, cancellationToken);
        var raised = await RaiseExpiringAsync(now, opts, cancellationToken)
                     + await RaiseStalledAsync(now, settings, opts, cancellationToken)
                     + await RaiseFailedAsync(now, settings, opts, cancellationToken);
        var queued = await DeliverAsync(now, cancellationToken);
        var pruned = await PruneAsync(now, opts, cancellationToken);
        return new NoticeSweepResult(resolved, raised, queued, pruned);
    }

    // ── Resolve ────────────────────────────────────────────────────────────────

    private async Task<int> ResolveAsync(DateTime now, CancellationToken ct)
    {
        var open = await db.Notices.Where(n => n.Status == NoticeStatus.Open).ToListAsync(ct);
        if (open.Count == 0) return 0;

        var requestIds = open.Select(n => n.RequestId).Distinct().ToList();
        var requests = await db.CertificateRequests.AsNoTracking()
            .Where(r => requestIds.Contains(r.Id))
            .Select(r => new RequestFacts { Id = r.Id, Status = r.Status, ValidTo = r.ValidTo, CreatedAtUtc = r.CreatedAtUtc })
            .ToDictionaryAsync(r => r.Id, ct);

        var expiringIds = open.Where(n => n.Kind == NoticeKind.Expiring).Select(n => n.RequestId).Distinct().ToList();
        var withRenewal = (await db.CertificateRequests.AsNoTracking()
                .Where(r => r.RenewedFromId != null && expiringIds.Contains(r.RenewedFromId.Value)
                            && r.Status != CertificateRequestStatus.Rejected && r.Status != CertificateRequestStatus.Revoked)
                .Select(r => r.RenewedFromId!.Value)
                .ToListAsync(ct))
            .ToHashSet();

        var resolved = 0;
        foreach (var notice in open)
        {
            if (!await StillHoldsAsync(notice, requests.GetValueOrDefault(notice.RequestId), withRenewal, now, ct))
            {
                notice.Status = NoticeStatus.Resolved;
                notice.ResolvedAtUtc = now;
                resolved++;
            }
        }

        // A less urgent open step left behind by an interrupted raise closes now: the smaller expiry threshold or
        // the higher escalation level is the one that stands.
        foreach (var group in open.Where(n => n.Status == NoticeStatus.Open).GroupBy(n => (n.RequestId, n.Kind)).Where(g => g.Count() > 1))
        {
            var standing = group.Key.Kind == NoticeKind.Expiring ? group.MinBy(n => n.Step)! : group.MaxBy(n => n.Step)!;
            foreach (var superseded in group.Where(n => n != standing))
            {
                superseded.Status = NoticeStatus.Resolved;
                superseded.ResolvedAtUtc = now;
                resolved++;
            }
        }

        if (resolved > 0) await db.SaveChangesAsync(ct);
        return resolved;
    }

    private sealed class RequestFacts
    {
        public CertificateRequestId Id { get; init; }
        public CertificateRequestStatus Status { get; init; }
        public DateTime? ValidTo { get; init; }
        public DateTime CreatedAtUtc { get; init; }
    }

    private async Task<bool> StillHoldsAsync(Notice notice, RequestFacts? request, HashSet<CertificateRequestId> withRenewal,
        DateTime now, CancellationToken ct)
    {
        if (request is null) return false;

        switch (notice.Kind)
        {
            case NoticeKind.Expiring:
                return request.Status == CertificateRequestStatus.Issued
                       && request.ValidTo is { } end && !NoticeRules.ExpiredPastGrace(end, now)
                       && !withRenewal.Contains(notice.RequestId);
            case NoticeKind.RenewalStalled:
                return request.Status == CertificateRequestStatus.Pending;
            case NoticeKind.RenewalFailed:
                if (request.Status != CertificateRequestStatus.Rejected) return false;
                // Replaced: a newer renewal of the same certificate means someone (or auto-renewal) tried again.
                var createdAt = request.CreatedAtUtc;
                return notice.SourceRequestId is not { } source
                       || !await db.CertificateRequests.AsNoTracking()
                           .AnyAsync(q => q.RenewedFromId == source && q.CreatedAtUtc > createdAt, ct);
            default:
                return false;
        }
    }

    // ── Raise ──────────────────────────────────────────────────────────────────

    private async Task<int> RaiseExpiringAsync(DateTime now, NoticesOptions opts, CancellationToken ct)
    {
        var horizon = now.AddDays(opts.ExpiryDayList.Max());
        // A CA is renewed by ceremony (never by a timer), and the Attention panel already watches CA and issuer expiry.
        var caTypeKeys = (await db.CertificateTemplates.AsNoTracking()
                .Select(t => new { t.TypeKey, t.KeyUsagesJson }).ToListAsync(ct))
            .Where(t => Policies.CaCapableTemplate.IsCaCapable(t.KeyUsagesJson))
            .Select(t => t.TypeKey)
            .Append(WellKnownCertificateTypes.RootCa)
            .ToList();
        var candidates = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Issued && r.ValidTo != null && r.ValidTo > now && r.ValidTo <= horizon)
            .Where(r => r.Type == null || !caTypeKeys.Contains(r.Type))
            .Where(r => !db.CertificateRequests.Any(q => q.RenewedFromId == r.Id
                        && q.Status != CertificateRequestStatus.Rejected && q.Status != CertificateRequestStatus.Revoked))
            .Select(r => new { r.Id, r.CommonName, ValidTo = r.ValidTo!.Value })
            .ToListAsync(ct);

        var existing = await ExistingStepsAsync(NoticeKind.Expiring, ct);
        var thresholds = opts.ExpiryDayList;
        var raised = 0;
        foreach (var c in candidates)
        {
            if (NoticeRules.ExpiryStep(c.ValidTo, now, thresholds) is not { } step) continue;
            // A smaller threshold is more urgent, so it supersedes the larger one raised earlier.
            if (await TryRaiseAsync(c.Id, null, c.CommonName, NoticeKind.Expiring, step, now, other => other > step, existing, ct))
                raised++;
        }
        return raised;
    }

    private async Task<int> RaiseStalledAsync(DateTime now, CaSettings settings, NoticesOptions opts, CancellationToken ct)
    {
        var cutoff = now.AddHours(-settings.AttentionPendingApprovalAgeHours);
        var stalled = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Pending && r.RenewedFromId != null && r.CreatedAtUtc < cutoff)
            .Select(r => new { r.Id, r.CommonName, Source = r.RenewedFromId!.Value })
            .ToListAsync(ct);

        var existing = await ExistingStepsAsync(NoticeKind.RenewalStalled, ct);
        var raised = 0;
        foreach (var r in stalled)
        {
            if (await TryRaiseAsync(r.Id, r.Source, r.CommonName, NoticeKind.RenewalStalled, 1, now, _ => false, existing, ct)) raised++;
        }
        return raised + await EscalateAsync(NoticeKind.RenewalStalled, now, opts, ct);
    }

    private async Task<int> RaiseFailedAsync(DateTime now, CaSettings settings, NoticesOptions opts, CancellationToken ct)
    {
        var since = now.AddDays(-settings.AttentionFailureLookbackDays);
        var failed = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Rejected && r.RenewedFromId != null
                        && r.FailureReason != null && r.FailureReason != "" && r.UpdatedAtUtc >= since)
            .Where(r => !db.CertificateRequests.Any(q => q.RenewedFromId == r.RenewedFromId && q.CreatedAtUtc > r.CreatedAtUtc))
            .Select(r => new { r.Id, r.CommonName, Source = r.RenewedFromId!.Value })
            .ToListAsync(ct);

        var existing = await ExistingStepsAsync(NoticeKind.RenewalFailed, ct);
        var raised = 0;
        foreach (var r in failed)
        {
            if (await TryRaiseAsync(r.Id, r.Source, r.CommonName, NoticeKind.RenewalFailed, 1, now, _ => false, existing, ct)) raised++;
        }
        return raised + await EscalateAsync(NoticeKind.RenewalFailed, now, opts, ct);
    }

    /// <summary>Level-1 notices still open after the gap repeat once at level 2.</summary>
    private async Task<int> EscalateAsync(NoticeKind kind, DateTime now, NoticesOptions opts, CancellationToken ct)
    {
        var due = (await db.Notices.AsNoTracking()
                .Where(n => n.Kind == kind && n.Step == 1 && n.Status == NoticeStatus.Open)
                .ToListAsync(ct))
            .Where(n => NoticeRules.EscalationDue(n.CreatedAtUtc, now, opts.EscalationAfterHours))
            .ToList();

        if (due.Count == 0) return 0;
        var dueIds = due.Select(n => n.RequestId).Distinct().ToList();
        var names = await db.CertificateRequests.AsNoTracking().Where(r => dueIds.Contains(r.Id))
            .Select(r => new { r.Id, r.CommonName }).ToDictionaryAsync(r => r.Id, r => r.CommonName, ct);
        var existing = await ExistingStepsAsync(kind, ct);
        var raised = 0;
        foreach (var notice in due)
        {
            if (await TryRaiseAsync(notice.RequestId, notice.SourceRequestId, names.GetValueOrDefault(notice.RequestId), kind, 2, now,
                    other => other < 2, existing, ct)) raised++;
        }
        return raised;
    }

    /// <summary>The (request, kind, step) triples already stored for <paramref name="kind"/>, read once per pass instead of once per candidate.</summary>
    private async Task<HashSet<(CertificateRequestId, NoticeKind, int)>> ExistingStepsAsync(NoticeKind kind, CancellationToken ct) =>
        (await db.Notices.AsNoTracking().Where(n => n.Kind == kind).Select(n => new { n.RequestId, n.Kind, n.Step }).ToListAsync(ct))
        .Select(n => (n.RequestId, n.Kind, n.Step))
        .ToHashSet();

    /// <summary>
    /// Inserts the notice unless its step already exists and, in the same save, closes the open notices of the same
    /// request and kind that <paramref name="supersedes"/> says the new step replaces, so an interruption cannot leave
    /// both open. Audits it afterwards.
    /// </summary>
    private async Task<bool> TryRaiseAsync(CertificateRequestId requestId, CertificateRequestId? source, string? commonName,
        NoticeKind kind, int step, DateTime now, Func<int, bool> supersedes,
        HashSet<(CertificateRequestId, NoticeKind, int)> existing, CancellationToken ct)
    {
        var key = (requestId, kind, step);
        if (existing.Contains(key)) return false;

        var notice = new Notice { RequestId = requestId, SourceRequestId = source, Kind = kind, Step = step, CreatedAtUtc = now };
        db.Notices.Add(notice);
        foreach (var older in await db.Notices
                     .Where(n => n.RequestId == requestId && n.Kind == kind && n.Status == NoticeStatus.Open)
                     .ToListAsync(ct))
        {
            if (!supersedes(older.Step)) continue;
            older.Status = NoticeStatus.Resolved;
            older.ResolvedAtUtc = now;
        }

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Another sweep inserted the same step first (the unique index is the arbiter), or the save failed for
            // another reason: only a stored row means "already raised"; anything else is a real failure.
            db.ChangeTracker.Clear();
            if (!await db.Notices.AsNoTracking().AnyAsync(n => n.RequestId == requestId && n.Kind == kind && n.Step == step, ct))
                throw;
            existing.Add(key);
            return false;
        }

        existing.Add(key);
        await auditLog.LogAsync("NoticeRaised", Actor, (Guid)requestId, commonName,
            string.Create(CultureInfo.InvariantCulture, $"{kind} step {step}"), ct);
        return true;
    }

    // ── Deliver ────────────────────────────────────────────────────────────────

    private async Task<int> DeliverAsync(DateTime now, CancellationToken ct)
    {
        var pending = await db.Notices.Where(n => n.Status == NoticeStatus.Open && n.WebhookQueuedAtUtc == null).ToListAsync(ct);
        var queued = 0;
        foreach (var notice in pending)
        {
            var row = await db.CertificateRequests.AsNoTracking().Where(r => r.Id == notice.RequestId)
                .Select(r => new { r.CommonName, r.ValidTo, r.FailureReason, r.Metadata })
                .FirstOrDefaultAsync(ct);
            if (row is null) continue;   // the request is gone; the next sweep resolves the notice

            // For the renewal kinds the expiry that matters is the certificate being renewed.
            var validTo = notice.Kind == NoticeKind.Expiring ? row.ValidTo
                : notice.SourceRequestId is { } source
                    ? await db.CertificateRequests.AsNoTracking().Where(r => r.Id == source).Select(r => r.ValidTo).FirstOrDefaultAsync(ct)
                    : null;

            await webhooks.EnqueueEventOrThrowAsync(new WebhookEvent(
                EventNameOf(notice.Kind), (Guid)notice.RequestId, row.CommonName, PerformedBy: Actor,
                Fields: new Dictionary<string, string?>(StringComparer.Ordinal)
                {
                    ["commonName"] = row.CommonName,
                    ["validTo"] = validTo?.ToString("O"),
                    ["daysLeft"] = validTo is { } end ? NoticeRules.DaysLeft(end, now).ToString(CultureInfo.InvariantCulture) : null,
                    ["level"] = (notice.Kind == NoticeKind.Expiring ? 1 : notice.Step).ToString(CultureInfo.InvariantCulture),
                    ["renewalId"] = notice.Kind == NoticeKind.Expiring ? null : notice.RequestId.ToString(),
                    ["failureReason"] = notice.Kind == NoticeKind.RenewalFailed ? row.FailureReason : null,
                    ["ownerTeam"] = row.Metadata.OwnerTeam,
                    ["contactEmail"] = row.Metadata.ContactEmail,
                    ["targetSystem"] = row.Metadata.TargetSystem,
                    ["ticketReference"] = row.Metadata.TicketReference
                }), ct);

            notice.WebhookQueuedAtUtc = now;
            await db.SaveChangesAsync(ct);
            queued++;
        }
        return queued;
    }

    private static string EventNameOf(NoticeKind kind) => kind switch
    {
        NoticeKind.Expiring => WellKnownWebhookEvents.CertificateExpiring,
        NoticeKind.RenewalStalled => WellKnownWebhookEvents.RenewalStalled,
        NoticeKind.RenewalFailed => WellKnownWebhookEvents.RenewalFailed,
        _ => throw new ArgumentOutOfRangeException(nameof(kind), kind, null)
    };

    // ── Prune ──────────────────────────────────────────────────────────────────

    private async Task<int> PruneAsync(DateTime now, NoticesOptions opts, CancellationToken ct)
    {
        var cutoff = now.AddDays(-opts.RetentionDays);
        // A resolved step is the once-only record for as long as its request and kind still have an open notice
        // (a superseded level 1 under an open level 2): deleting it would raise the step, and its webhook, again.
        return await db.Notices
            .Where(n => n.Status == NoticeStatus.Resolved && n.ResolvedAtUtc < cutoff
                        && !db.Notices.Any(o => o.RequestId == n.RequestId && o.Kind == n.Kind && o.Status == NoticeStatus.Open))
            .ExecuteDeleteAsync(ct);
    }
}
