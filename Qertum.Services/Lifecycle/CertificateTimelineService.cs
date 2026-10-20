using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Lifecycle;

/// <summary>
/// What the caller may see. Resolved by the endpoint: the permission policies succeed only with the
/// request's <c>HttpContext</c> as resource, and key access is the owner-or-admin evaluator's call.
/// </summary>
public sealed record TimelineAccess(bool CanEditSettings, bool CanSeeKeyExports, string? CallerSubject = null);

/// <summary>Builds a certificate request's timeline. Read-only.</summary>
public interface ICertificateTimelineService
{
    /// <summary>The timeline, or null when the request does not exist.</summary>
    Task<CertificateTimelineResponse?> GetAsync(CertificateRequestId id, TimelineAccess access,
        CancellationToken cancellationToken = default);
}

public sealed class CertificateTimelineService(CertificateRequestDbContext db) : ICertificateTimelineService
{
    private static readonly HashSet<string> KeyExportActions = new(StringComparer.Ordinal) { "PrivateKeyDownloaded", "PfxExported" };

    public async Task<CertificateTimelineResponse?> GetAsync(CertificateRequestId id, TimelineAccess access,
        CancellationToken cancellationToken = default)
    {
        var request = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.Id == id)
            .Select(r => new
            {
                r.Id, r.CommonName, r.Status, r.SerialNumber, r.ValidFrom, r.ValidTo, r.CreatedAtUtc,
                r.RevokedAtUtc, r.RevocationReason, r.RenewedFromId, r.RequestedBy
            })
            .FirstOrDefaultAsync(cancellationToken);
        if (request is null) return null;

        Guid subjectId = id;
        var entries = new List<TimelineEntry>();
        var withheld = new Dictionary<TimelineSection, int>();
        if (!access.CanEditSettings)
        {
            withheld[TimelineSection.WebhookDeliveries] = 0;
            withheld[TimelineSection.Diagnostics] = 0;
        }
        if (!access.CanSeeKeyExports)
            withheld[TimelineSection.KeyExports] = 0;

        var events = await db.LifecycleEvents.AsNoTracking()
            .Where(e => e.SubjectType == LifecycleSubjectTypes.CertificateRequest && e.SubjectId == subjectId)
            .ToListAsync(cancellationToken);
        foreach (var e in events)
        {
            // The note itself is the entry; its add and edit audit rows would only repeat it. A delete leaves no note, so that row stays.
            if (e.Kind == LifecycleEventKinds.Audit && (e.Action is "NoteAdded" or "NoteEdited"))
                continue;
            if (e.Kind == LifecycleEventKinds.Diagnostic && !access.CanEditSettings)
            {
                withheld[TimelineSection.Diagnostics]++;
                continue;
            }
            if (KeyExportActions.Contains(e.Action) && !access.CanSeeKeyExports)
            {
                withheld[TimelineSection.KeyExports]++;
                continue;
            }
            entries.Add(new TimelineEntry
            {
                OccurredAtUtc = e.OccurredAtUtc,
                Kind = e.Kind == LifecycleEventKinds.Diagnostic ? TimelineEntryKind.Diagnostic : TimelineEntryKind.Audit,
                Action = e.Action,
                Category = e.Category,
                PerformedBy = e.PerformedBy,
                Detail = e.Detail,
                Hint = DiagnosticHints.For(e.Category),
            });
        }

        // The ACME order that filed this request, once finalize linked one: how it was obtained.
        var orderIds = await db.AcmeOrders.AsNoTracking()
            .Where(o => o.CertificateRequestId == subjectId)
            .Select(o => o.Id)
            .ToListAsync(cancellationToken);
        if (orderIds.Count > 0)
        {
            var orderEvents = await db.LifecycleEvents.AsNoTracking()
                .Where(e => e.SubjectType == LifecycleSubjectTypes.AcmeOrder && orderIds.Contains(e.SubjectId))
                .ToListAsync(cancellationToken);
            if (access.CanEditSettings)
                entries.AddRange(orderEvents.Select(Acme.AcmeOrderQueryService.ToEntry));
            else
                withheld[TimelineSection.Diagnostics] += orderEvents.Count;
        }

        // Milestones from the request's own columns, only where no event says the same thing, so a
        // certificate from before event recording still has a history.
        var recorded = events.Select(e => e.Action).ToHashSet(StringComparer.Ordinal);
        if (!recorded.Contains("Created"))
            entries.Add(Milestone("Created", request.CreatedAtUtc, $"Requested by {request.RequestedBy}"));
        if (request.ValidFrom is { } validFrom && !recorded.Contains("Issued"))
            entries.Add(Milestone("Issued", validFrom, null));
        if (request.RevokedAtUtc is { } revokedAt && !recorded.Contains("Revoked"))
            entries.Add(Milestone("Revoked", revokedAt,
                string.IsNullOrWhiteSpace(request.RevocationReason) ? null : $"Reason: {request.RevocationReason}"));

        var notes = await db.CertificateNotes.AsNoTracking()
            .Where(n => n.RequestId == id)
            .OrderBy(n => n.CreatedAtUtc)
            .ToListAsync(cancellationToken);
        entries.AddRange(notes.Select(n => new TimelineEntry
        {
            OccurredAtUtc = n.CreatedAtUtc, Kind = TimelineEntryKind.Note, Action = "Note",
            PerformedBy = n.AuthorName, Detail = n.Body, NoteId = n.Id, UpdatedAtUtc = n.UpdatedAtUtc,
            Edited = n.UpdatedAtUtc > n.CreatedAtUtc,
            Mine = !string.IsNullOrWhiteSpace(access.CallerSubject)
                   && string.Equals(n.AuthorSubject, access.CallerSubject, StringComparison.Ordinal)
        }));

        var relatedIds = new List<CertificateRequestId>();
        if (request.RenewedFromId is { } renewedFrom)
        {
            entries.Add(new TimelineEntry
            {
                OccurredAtUtc = request.CreatedAtUtc, Kind = TimelineEntryKind.Renewal,
                Action = "RenewedFrom", RelatedRequestId = renewedFrom
            });
            relatedIds.Add(renewedFrom);
        }
        CertificateRequestId? self = id;
        var successors = await db.CertificateRequests.AsNoTracking()
            .Where(r => r.RenewedFromId == self)
            .Select(r => new { r.Id, r.CreatedAtUtc })
            .ToListAsync(cancellationToken);
        foreach (var successor in successors)
        {
            entries.Add(new TimelineEntry
            {
                OccurredAtUtc = successor.CreatedAtUtc, Kind = TimelineEntryKind.Renewal,
                Action = "RenewedAs", RelatedRequestId = successor.Id
            });
            relatedIds.Add(successor.Id);
        }

        var noteCounts = relatedIds.Count == 0
            ? new Dictionary<CertificateRequestId, int>()
            : await db.CertificateNotes.AsNoTracking()
                .Where(n => relatedIds.Contains(n.RequestId))
                .GroupBy(n => n.RequestId)
                .Select(g => new { RequestId = g.Key, Count = g.Count() })
                .ToDictionaryAsync(g => g.RequestId, g => g.Count, cancellationToken);
        var relatedRows = relatedIds.Count == 0
            ? []
            : await db.CertificateRequests.AsNoTracking()
                .Where(r => relatedIds.Contains(r.Id))
                .Select(r => new { r.Id, r.CommonName, r.Status, r.SerialNumber, r.ValidFrom, r.ValidTo })
                .ToListAsync(cancellationToken);
        var related = relatedRows.Select(r => new TimelineCertificateSummary
        {
            Id = r.Id, CommonName = r.CommonName, Status = r.Status, SerialNumber = r.SerialNumber,
            ValidFrom = r.ValidFrom, ValidTo = r.ValidTo, NoteCount = noteCounts.GetValueOrDefault(r.Id)
        }).ToList();

        // Payload and ResolvedUrl are never selected: the same rule the attention view follows.
        var deliveries = await db.WebhookDeliveries.AsNoTracking()
            .Where(d => d.ResourceId == subjectId)
            .Select(d => new { d.EventType, d.Status, d.AttemptCount, d.NextAttemptAfterUtc, d.LastErrorMessage, d.CreatedAtUtc })
            .ToListAsync(cancellationToken);
        if (access.CanEditSettings)
            entries.AddRange(deliveries.Select(d => new TimelineEntry
            {
                OccurredAtUtc = d.CreatedAtUtc,
                Kind = TimelineEntryKind.WebhookDelivery,
                Action = d.EventType,
                Category = d.Status,
                Detail = d.Status == "Pending"
                    ? $"Attempt {d.AttemptCount}; next attempt at {d.NextAttemptAfterUtc:yyyy-MM-dd HH:mm} UTC"
                    : d.LastErrorMessage,
            }));
        else
            withheld[TimelineSection.WebhookDeliveries] = deliveries.Count;

        var firstEventAt = await db.LifecycleEvents.MinAsync(e => (DateTime?)e.OccurredAtUtc, cancellationToken);

        return new CertificateTimelineResponse
        {
            Subject = new TimelineCertificateSummary
            {
                Id = request.Id, CommonName = request.CommonName, Status = request.Status,
                SerialNumber = request.SerialNumber, ValidFrom = request.ValidFrom, ValidTo = request.ValidTo
            },
            Entries = entries.OrderBy(e => e.OccurredAtUtc).ToList(),
            Related = related,
            Withheld = withheld.OrderBy(w => w.Key)
                .Select(w => new WithheldTimelineSection { Section = w.Key, Count = w.Value })
                .ToList(),
            Completeness = firstEventAt is null || request.CreatedAtUtc < firstEventAt
                ? TimelineCompleteness.PartialBeforeUpgrade
                : TimelineCompleteness.Full,
        };
    }

    private static TimelineEntry Milestone(string action, DateTime at, string? detail) => new()
    {
        OccurredAtUtc = at, Kind = TimelineEntryKind.Record, Action = action, Detail = detail
    };
}
