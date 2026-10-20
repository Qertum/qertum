using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Dashboard;

/// <summary>What the caller may see. Resolved by the endpoint, because the permission policies only
/// succeed when the authorization resource is the request's <c>HttpContext</c>.</summary>
/// <param name="CanViewCertificates">Holds certificates.view.</param>
/// <param name="CanEditSettings">Holds settings.edit.</param>
/// <param name="IsAdmin">Holds the administrator role (who can decide approvals).</param>
/// <param name="Subject">The caller's subject, so their own approval requests are not counted as waiting for them.</param>
public sealed record AttentionAccess(bool CanViewCertificates, bool CanEditSettings, bool IsAdmin = false, string? Subject = null);

/// <summary>Builds the dashboard's attention report. Read-only: writes nothing.</summary>
public interface IAttentionService
{
    /// <summary>
    /// Runs every check the caller is permitted to run and reports the conditions that hold. A check
    /// the caller may not run is not executed and is listed in <see cref="AttentionReport.WithheldKinds"/>;
    /// a check that throws is listed in <see cref="AttentionReport.UnavailableKinds"/>.
    /// </summary>
    Task<AttentionReport> GetReportAsync(AttentionAccess access, CancellationToken cancellationToken = default);
}

internal sealed class AttentionService(
    CertificateRequestDbContext db,
    ICertificateGenerator certificateGenerator,
    TimeProvider timeProvider,
    ILogger<AttentionService> logger,
    Issuers.IIssuerRegistry? issuers = null,
    Recovery.IRecoveryStatusService? recovery = null,
    Microsoft.Extensions.Options.IOptions<Approvals.ApprovalOptions>? approvalOptions = null) : IAttentionService
{
    internal const int EvidenceLimit = 5;

    public async Task<AttentionReport> GetReportAsync(AttentionAccess access, CancellationToken cancellationToken = default)
    {
        var now = timeProvider.GetUtcNow().UtcDateTime;

        // Read-only on purpose: ICertificateRequestService.GetSettingsAsync inserts the singleton
        // row when it is missing, and this report must not write anything.
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, cancellationToken)
                       ?? new CaSettings { Id = 1 };

        var checks = new (AttentionKind Kind, bool Permitted, Func<Task<AttentionItem?>> Run)[]
        {
            (AttentionKind.AgingApprovals, access.CanViewCertificates, () => AgingApprovalsAsync(settings, now, cancellationToken)),
            (AttentionKind.FailedIssuance, access.CanViewCertificates, () => FailedIssuanceAsync(settings, now, cancellationToken)),
            (AttentionKind.FailedWebhookDeliveries, access.CanEditSettings, () => FailedWebhookDeliveriesAsync(settings, now, cancellationToken)),
            (AttentionKind.DeltaCrlBase, access.CanEditSettings, () => Task.FromResult(DeltaCrlBase(settings, now))),
            (AttentionKind.CaExpiry, access.CanEditSettings, () => CaExpiryAsync(settings, now, cancellationToken)),
            (AttentionKind.IssuerExpiring, access.CanEditSettings, () => IssuerExpiringAsync(now, cancellationToken)),
            (AttentionKind.RootCrlExpiring, access.CanEditSettings, () => RootCrlExpiringAsync(now, cancellationToken)),
            (AttentionKind.IssuerArchivable, access.CanEditSettings, () => IssuerArchivableAsync(now, cancellationToken)),
            (AttentionKind.IssuerRevoked, access.CanEditSettings, () => IssuerRevokedAsync(cancellationToken)),
            (AttentionKind.PqcExceptionExpiring, access.CanEditSettings, () => PqcExceptionExpiringAsync(now, cancellationToken)),
            (AttentionKind.RecoveryStatus, access.CanEditSettings, () => Task.FromResult(RecoveryStatusItem(settings, now))),
            (AttentionKind.OpenNotices, access.CanViewCertificates, () => OpenNoticesAsync(cancellationToken)),
            (AttentionKind.ApprovalsWaiting, access.IsAdmin, () => ApprovalsWaitingAsync(access.Subject, now, cancellationToken)),
        };

        var items = new List<AttentionItem>();
        var withheld = new List<AttentionKind>();
        var unavailable = new List<AttentionKind>();

        foreach (var (kind, permitted, run) in checks)
        {
            if (!permitted)
            {
                withheld.Add(kind);
                continue;
            }

            try
            {
                if (await run() is { } item)
                    items.Add(item);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // One broken check must not blank the whole report — but its state is unknown, and
                // the UI must never read an unknown as "nothing wrong".
                logger.LogWarning(ex, "Attention check {Kind} failed; reporting it as unavailable.", kind);
                unavailable.Add(kind);
            }
        }

        return new AttentionReport
        {
            GeneratedAtUtc = now,
            Items = items.OrderByDescending(i => i.Severity).ThenBy(i => i.Kind).ToList(),
            WithheldKinds = withheld,
            UnavailableKinds = unavailable
        };
    }

    /// <summary>
    /// Stale or unreadable recovery records. "Not reported" is not an item: a deployment may back up
    /// another way, and the attention model has no informational severity. Everything here was reported
    /// by a script on the host; Qertum has not verified it.
    /// </summary>
    private AttentionItem? RecoveryStatusItem(CaSettings settings, DateTime now)
    {
        if (recovery is null)
            return null;

        var status = recovery.Evaluate(settings, now);
        var problems = new List<(string Title, AttentionEvidence Evidence)>();
        AddRecoveryProblem(problems, "backup", "Last backup", status.Backup, status.GeneratedAtUtc);
        AddRecoveryProblem(problems, "verified restore", "Last restore test", status.Restore, status.GeneratedAtUtc);
        if (problems.Count == 0)
            return null;

        return new AttentionItem
        {
            Kind = AttentionKind.RecoveryStatus,
            Severity = AttentionSeverity.Warning,
            Count = problems.Count,
            Title = problems.Count == 1 ? problems[0].Title : $"{problems.Count} recovery checks need attention",
            Explanation = "This is what the backup script on the host reported. Qertum has not checked the archive or that a restore works. A stale record means no recent run was reported; an unreadable one means the script's status file is damaged. A failed restore test means the archive or the restored data did not pass; run restore-test again and read its output.",
            Evidence = problems.Select(p => p.Evidence).ToList(),
            ActionLabel = "Open backup status",
            ActionHref = "/settings?section=system"
        };
    }

    private static void AddRecoveryProblem(
        List<(string Title, AttentionEvidence Evidence)> problems, string noun, string label, RecoveryItem item, DateTime now)
    {
        switch (item.State)
        {
            case RecoveryItemState.Stale:
                var age = now - item.CompletedAtUtc!.Value;
                var limit = FormatHours(item.ThresholdHours!.Value);
                problems.Add(($"Last reported {noun} is {FormatAge(age)} old (limit {limit})", new AttentionEvidence
                {
                    Label = label,
                    Detail = $"{item.ArchiveName ?? "unnamed archive"}, finished {FormatAge(age)} ago; the limit is {limit}",
                    OccurredAtUtc = item.CompletedAtUtc
                }));
                break;
            case RecoveryItemState.Unreadable:
                problems.Add(($"The reported {noun} record cannot be read", new AttentionEvidence
                {
                    Label = $"{label} record",
                    Detail = item.Problem
                }));
                break;
            case RecoveryItemState.Failed:
                problems.Add(($"The last restore test failed at {item.FailedCheck}", new AttentionEvidence
                {
                    Label = label,
                    Detail = $"{item.ArchiveName ?? "unnamed archive"}, {item.Step} step, finished {FormatAge(now - item.CompletedAtUtc!.Value)} ago",
                    OccurredAtUtc = item.CompletedAtUtc
                }));
                break;
        }
    }

    private async Task<AttentionItem?> ApprovalsWaitingAsync(string? subject, DateTime now, CancellationToken ct)
    {
        var cutoff = now.AddHours(-(approvalOptions?.Value ?? new Approvals.ApprovalOptions()).RequestTtlHours);
        var query = db.ApprovalRequests.AsNoTracking()
            .Where(a => a.Status == ApprovalStatus.Pending && a.RequestedAtUtc > cutoff && a.RequestedBySubject != subject);
        var count = await query.CountAsync(ct);
        if (count == 0)
            return null;

        var newest = await query.OrderBy(a => a.RequestedAtUtc).Take(EvidenceLimit).ToListAsync(ct);
        return new AttentionItem
        {
            Kind = AttentionKind.ApprovalsWaiting,
            Severity = AttentionSeverity.Warning,
            Count = count,
            Title = $"{count} {Plural(count, "request", "requests")} for approval {Plural(count, "is", "are")} waiting for you",
            Explanation = "Another administrator asked for a second person's approval of a sensitive operation. They cannot perform it until you approve or deny it.",
            Evidence = newest.Select(a => new AttentionEvidence
            {
                Label = a.Operation,
                Detail = $"requested by {a.RequestedByName}",
                Href = "/approvals",
                OccurredAtUtc = a.RequestedAtUtc
            }).ToList(),
            ActionLabel = "Open approvals",
            ActionHref = "/approvals"
        };
    }

    private async Task<AttentionItem?> OpenNoticesAsync(CancellationToken ct)
    {
        var query = db.Notices.AsNoTracking().Where(n => n.Status == NoticeStatus.Open);
        var count = await query.CountAsync(ct);
        if (count == 0)
            return null;

        var newest = await query.OrderByDescending(n => n.CreatedAtUtc).Take(EvidenceLimit).ToListAsync(ct);
        var ids = newest.Select(n => n.RequestId).Distinct().ToList();
        var names = await db.CertificateRequests.AsNoTracking().Where(r => ids.Contains(r.Id))
            .Select(r => new { r.Id, r.CommonName }).ToDictionaryAsync(r => r.Id, r => r.CommonName, ct);

        return new AttentionItem
        {
            Kind = AttentionKind.OpenNotices,
            Severity = AttentionSeverity.Warning,
            Count = count,
            Title = $"{count} open {Plural(count, "notice", "notices")} about certificate renewal",
            Explanation = "A certificate is close to expiry, or a renewal is waiting for approval or has failed. A notice closes by itself when the situation ends.",
            Evidence = newest.Select(n => new AttentionEvidence
            {
                Label = names.GetValueOrDefault(n.RequestId) ?? "(request no longer exists)",
                Detail = NoticeDescriptions.Describe(n.Kind, n.Step),
                Href = $"/certificate-requests/{(Guid)n.RequestId}",
                OccurredAtUtc = n.CreatedAtUtc
            }).ToList(),
            ActionLabel = "Open notices",
            ActionHref = "/notices"
        };
    }

    private async Task<AttentionItem?> AgingApprovalsAsync(CaSettings settings, DateTime now, CancellationToken ct)
    {
        var thresholdHours = settings.AttentionPendingApprovalAgeHours;
        var cutoff = now.AddHours(-thresholdHours);
        var query = db.CertificateRequests.AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Pending && r.CreatedAtUtc < cutoff);

        var count = await query.CountAsync(ct);
        if (count == 0)
            return null;

        var oldest = await query
            .OrderBy(r => r.CreatedAtUtc)
            .Take(EvidenceLimit)
            .Select(r => new { r.Id, r.CommonName, r.RequestedBy, r.CreatedAtUtc })
            .ToListAsync(ct);

        return new AttentionItem
        {
            Kind = AttentionKind.AgingApprovals,
            Severity = AttentionSeverity.Warning,
            Count = count,
            Title = $"{count} {Plural(count, "request", "requests")} waiting for approval longer than {FormatHours(thresholdHours)}",
            Explanation = "These requests are still Pending. Nothing is issued until someone with certificates.manage approves or rejects them.",
            Evidence = oldest.Select(r => new AttentionEvidence
            {
                Label = r.CommonName,
                Detail = $"Requested by {r.RequestedBy}, waiting {FormatAge(now - r.CreatedAtUtc)}",
                Href = $"/certificate-requests/{(Guid)r.Id}",
                OccurredAtUtc = r.CreatedAtUtc
            }).ToList(),
            ActionLabel = "Review pending requests",
            ActionHref = "/certificate-requests"
        };
    }

    private async Task<AttentionItem?> FailedIssuanceAsync(CaSettings settings, DateTime now, CancellationToken ct)
    {
        var lookbackDays = settings.AttentionFailureLookbackDays;
        var since = now.AddDays(-lookbackDays);

        // A human rejection passes a null FailureReason; only the queue consumer (retries exhausted)
        // and the pre-signing policy check set one. That is the whole discriminator.
        var query = db.CertificateRequests.AsNoTracking()
            .Where(r => r.Status == CertificateRequestStatus.Rejected
                        && r.FailureReason != null && r.FailureReason != ""
                        && r.UpdatedAtUtc >= since);

        var count = await query.CountAsync(ct);
        if (count == 0)
            return null;

        var newest = await query
            .OrderByDescending(r => r.UpdatedAtUtc)
            .Take(EvidenceLimit)
            .Select(r => new { r.Id, r.CommonName, r.FailureReason, r.UpdatedAtUtc })
            .ToListAsync(ct);

        return new AttentionItem
        {
            Kind = AttentionKind.FailedIssuance,
            Severity = AttentionSeverity.Warning,
            Count = count,
            Title = $"{count} {Plural(count, "request", "requests")} failed issuance in the last {FormatDays(lookbackDays)}",
            Explanation = "The issuance pipeline rejected these requests after retries or a policy check. Human denials are not included. A fixed cause does not re-issue them — renew or resubmit.",
            Evidence = newest.Select(r => new AttentionEvidence
            {
                Label = r.CommonName,
                Detail = r.FailureReason,
                Href = $"/certificate-requests/{(Guid)r.Id}",
                OccurredAtUtc = r.UpdatedAtUtc
            }).ToList(),
            ActionLabel = "Review rejected requests",
            ActionHref = "/denied"
        };
    }

    private async Task<AttentionItem?> FailedWebhookDeliveriesAsync(CaSettings settings, DateTime now, CancellationToken ct)
    {
        var lookbackDays = settings.AttentionFailureLookbackDays;
        var since = now.AddDays(-lookbackDays);

        // Only the columns evidence needs. Payload and ResolvedUrl are never selected: a resolved
        // URL can carry placeholder values taken from the event.
        var failures = await db.WebhookDeliveries.AsNoTracking()
            .Where(d => d.Status == "Failed" && d.CreatedAtUtc >= since)
            .OrderByDescending(d => d.CreatedAtUtc)
            .Select(d => new { d.WebhookId, d.LastErrorMessage, d.CreatedAtUtc })
            .ToListAsync(ct);

        if (failures.Count == 0)
            return null;

        var names = await db.Webhooks.AsNoTracking()
            .Select(w => new { w.Id, w.Name })
            .ToDictionaryAsync(w => w.Id, w => w.Name, ct);

        // Grouped in memory: the set is bounded by the lookback window and five attempts per event.
        var perWebhook = failures
            .GroupBy(f => f.WebhookId)
            .Select(g => new { WebhookId = g.Key, Count = g.Count(), Latest = g.First() })
            .OrderByDescending(g => g.Count)
            .ThenByDescending(g => g.Latest.CreatedAtUtc)
            .Take(EvidenceLimit)
            .ToList();

        return new AttentionItem
        {
            Kind = AttentionKind.FailedWebhookDeliveries,
            Severity = AttentionSeverity.Warning,
            Count = failures.Count,
            Title = $"{failures.Count} webhook {Plural(failures.Count, "delivery", "deliveries")} failed in the last {FormatDays(lookbackDays)}",
            Explanation = "A delivery is marked failed after 5 attempts and is not retried again. The receiver did not get these events.",
            Evidence = perWebhook.Select(g => new AttentionEvidence
            {
                Label = names.TryGetValue(g.WebhookId, out var name) ? name : "(deleted webhook)",
                Detail = $"{g.Count} failed; last error: {Truncate(g.Latest.LastErrorMessage, 300) ?? "none recorded"}",
                Href = "/webhooks",
                OccurredAtUtc = g.Latest.CreatedAtUtc
            }).ToList(),
            ActionLabel = "Review webhooks",
            ActionHref = "/webhooks"
        };
    }

    private static AttentionItem? DeltaCrlBase(CaSettings settings, DateTime now)
    {
        if (!settings.DeltaCrlEnabled)
            return null;

        const string explanation =
            "Delta CRLs are computed against the most recent full CRL, which is only republished when something fetches /crl. " +
            "Clients that fetch only /crl/delta never refresh it. Resetting the base publishes a fresh full CRL now.";

        if (settings.BaseCrlThisUpdateUtc is not { } baseUpdate)
        {
            return new AttentionItem
            {
                Kind = AttentionKind.DeltaCrlBase,
                Severity = AttentionSeverity.Warning,
                Count = 1,
                Title = "Delta CRLs are enabled but no full CRL base has been published",
                Explanation = explanation,
                ActionLabel = "Reset delta CRL base",
                ActionHref = "/settings"
            };
        }

        var publishedUtc = AsUtc(baseUpdate);
        var lapsesUtc = publishedUtc.AddHours(settings.CrlValidityHours);
        var remaining = lapsesUtc - now;

        AttentionSeverity severity;
        string title;
        if (remaining <= TimeSpan.Zero)
        {
            severity = AttentionSeverity.Critical;
            title = $"Delta CRL base lapsed {FormatAge(-remaining)} ago";
        }
        else if (remaining <= TimeSpan.FromHours(settings.DeltaCrlValidityHours))
        {
            // Less than one delta lifetime left: a delta issued now would outlive its base.
            severity = AttentionSeverity.Warning;
            title = $"Delta CRL base lapses in {FormatAge(remaining)}";
        }
        else
        {
            return null;
        }

        return new AttentionItem
        {
            Kind = AttentionKind.DeltaCrlBase,
            Severity = severity,
            Count = 1,
            Title = title,
            Explanation = explanation,
            Evidence =
            [
                new AttentionEvidence
                {
                    Label = $"CRL #{settings.BaseCrlNumber}",
                    Detail = $"Published {publishedUtc.ToString("u", CultureInfo.InvariantCulture)}, valid until {lapsesUtc.ToString("u", CultureInfo.InvariantCulture)}",
                    Href = "/settings",
                    OccurredAtUtc = publishedUtc
                }
            ],
            ActionLabel = "Reset delta CRL base",
            ActionHref = "/settings"
        };
    }

    private async Task<AttentionItem?> CaExpiryAsync(CaSettings settings, DateTime now, CancellationToken ct)
    {
        // The default issuer is "the CA" relying parties see; without a registry, the legacy files.
        var status = (issuers is null ? null : (await issuers.GetDefaultAsync(ct))?.Generator?.GetCaStatus())
                     ?? certificateGenerator.GetCaStatus();

        // An uninitialized CA belongs to onboarding and CaFilesHealthCheck, not to this view.
        if (!status.IsInitialized || status.ValidTo is not { } validTo)
            return null;

        var expiresUtc = AsUtc(validTo);
        var remaining = expiresUtc - now;

        AttentionSeverity severity;
        string title;
        if (remaining <= TimeSpan.Zero)
        {
            severity = AttentionSeverity.Critical;
            title = "CA certificate has expired";
        }
        else if (remaining <= TimeSpan.FromDays(settings.ExpiringSoonDays))
        {
            severity = AttentionSeverity.Warning;
            var daysLeft = (int)Math.Ceiling(remaining.TotalDays);
            title = $"CA certificate expires in {FormatDays(daysLeft)}";
        }
        else
        {
            return null;
        }

        return new AttentionItem
        {
            Kind = AttentionKind.CaExpiry,
            Severity = severity,
            Count = 1,
            Title = title,
            Explanation = "Every certificate this CA issued stops validating when the CA certificate expires. Plan a replacement and distribute the new trust anchor before then.",
            Evidence =
            [
                new AttentionEvidence
                {
                    Label = status.SubjectDn ?? "CA certificate",
                    Detail = $"Valid until {expiresUtc.ToString("u", CultureInfo.InvariantCulture)}",
                    Href = "/settings",
                    OccurredAtUtc = expiresUtc
                }
            ],
            ActionLabel = "Open CA settings",
            ActionHref = "/settings"
        };
    }

    private const string IssuersHref = "/issuers";
    internal static readonly TimeSpan IssuerExpiryWindow = TimeSpan.FromDays(90);
    internal static readonly TimeSpan RootCrlWindow = TimeSpan.FromDays(30);

    private async Task<AttentionItem?> IssuerExpiringAsync(DateTime now, CancellationToken ct)
    {
        var horizon = now + IssuerExpiryWindow;
        var rows = await db.Issuers.AsNoTracking()
            .Where(i => (i.Status == IssuerStatus.Active || i.Status == IssuerStatus.Retired) && i.ValidTo != null && i.ValidTo <= horizon)
            .OrderBy(i => i.ValidTo)
            .ToListAsync(ct);
        if (rows.Count == 0) return null;

        var expired = rows.Count(i => AsUtc(i.ValidTo!.Value) <= now);
        return new AttentionItem
        {
            Kind = AttentionKind.IssuerExpiring,
            Severity = expired > 0 ? AttentionSeverity.Critical : AttentionSeverity.Warning,
            Count = rows.Count,
            Title = expired > 0
                ? $"{expired} {Plural(expired, "issuer certificate has", "issuer certificates have")} expired"
                : $"{rows.Count} {Plural(rows.Count, "issuer certificate expires", "issuer certificates expire")} within 90 days",
            Explanation = "Certificates an issuer signed stop validating when its own certificate ends. Create a successor, make it the default and retire the old issuer before then.",
            Evidence = rows.Take(EvidenceLimit).Select(i => new AttentionEvidence
            {
                Label = i.Name,
                Detail = $"Valid until {AsUtc(i.ValidTo!.Value).ToString("u", CultureInfo.InvariantCulture)}",
                Href = IssuersHref,
                OccurredAtUtc = AsUtc(i.ValidTo!.Value)
            }).ToList(),
            ActionLabel = "Open issuers",
            ActionHref = IssuersHref
        };
    }

    private async Task<AttentionItem?> RootCrlExpiringAsync(DateTime now, CancellationToken ct)
    {
        var horizon = now + RootCrlWindow;
        // Only offline issuers anchoring an active intermediate matter: nothing else relies on their CRL.
        var rows = await db.Issuers.AsNoTracking()
            .Where(i => i.KeyCustody == IssuerKeyCustody.Offline &&
                        (i.Status == IssuerStatus.Active || i.Status == IssuerStatus.Retired) &&
                        db.Issuers.Any(c => c.ParentIssuerId == i.Id && c.Status == IssuerStatus.Active) &&
                        (i.UploadedCrlNextUpdateUtc == null || i.UploadedCrlNextUpdateUtc <= horizon))
            .OrderBy(i => i.Name)
            .ToListAsync(ct);
        if (rows.Count == 0) return null;

        var lapsed = rows.Count(i => i.UploadedCrlNextUpdateUtc is not { } next || AsUtc(next) <= now);
        return new AttentionItem
        {
            Kind = AttentionKind.RootCrlExpiring,
            Severity = lapsed > 0 ? AttentionSeverity.Critical : AttentionSeverity.Warning,
            Count = rows.Count,
            Title = lapsed > 0
                ? $"{lapsed} offline {Plural(lapsed, "issuer has", "issuers have")} no current CRL"
                : $"{rows.Count} offline {Plural(rows.Count, "issuer's CRL expires", "issuers' CRLs expire")} within 30 days",
            Explanation = "Relying parties that check revocation reject intermediates whose root CRL is missing or stale. Sign a fresh CRL on the offline machine (qca root crl) and upload it.",
            Evidence = rows.Take(EvidenceLimit).Select(i => new AttentionEvidence
            {
                Label = i.Name,
                Detail = i.UploadedCrlNextUpdateUtc is { } next
                    ? $"CRL next update {AsUtc(next).ToString("u", CultureInfo.InvariantCulture)}"
                    : "No CRL uploaded",
                Href = IssuersHref,
                OccurredAtUtc = i.UploadedCrlNextUpdateUtc is { } at ? AsUtc(at) : null
            }).ToList(),
            ActionLabel = "Upload a CRL",
            ActionHref = IssuersHref
        };
    }

    private async Task<AttentionItem?> IssuerArchivableAsync(DateTime now, CancellationToken ct)
    {
        var retired = await db.Issuers.AsNoTracking()
            .Where(i => i.Status == IssuerStatus.Retired)
            .OrderBy(i => i.RetiredAtUtc)
            .ToListAsync(ct);
        var archivable = new List<Issuer>();
        foreach (var issuer in retired)
            if (await Issuers.IssuerQueries.UnexpiredCountAsync(db, issuer, now, ct) == 0)
                archivable.Add(issuer);
        if (archivable.Count == 0) return null;

        return new AttentionItem
        {
            Kind = AttentionKind.IssuerArchivable,
            Severity = AttentionSeverity.Warning,
            Count = archivable.Count,
            Title = $"{archivable.Count} retired {Plural(archivable.Count, "issuer", "issuers")} can be archived",
            Explanation = "Nothing these issuers signed is still valid. Archiving deletes their keys, which removes a key that could otherwise still sign.",
            Evidence = archivable.Take(EvidenceLimit).Select(i => new AttentionEvidence
            {
                Label = i.Name,
                Detail = "Nothing it signed is still valid",
                Href = IssuersHref,
                OccurredAtUtc = i.RetiredAtUtc is { } at ? AsUtc(at) : null
            }).ToList(),
            ActionLabel = "Open issuers",
            ActionHref = IssuersHref
        };
    }

    /// <summary>Days before an exception ends at which it is reported.</summary>
    internal const int PqcExceptionWarningDays = 14;

    private const string PqcExceptionsHref = "/pqc-exceptions";

    // Evidence names the template and the end date only: the reading of exceptions (name patterns,
    // reasons) is admin-only, and this report is open to every settings.edit holder.
    private async Task<AttentionItem?> PqcExceptionExpiringAsync(DateTime now, CancellationToken ct)
    {
        var horizon = now.AddDays(PqcExceptionWarningDays);
        var query = db.PqcExceptions.AsNoTracking()
            .Where(e => e.RevokedAtUtc == null && e.ExpiresAtUtc > now && e.ExpiresAtUtc <= horizon);

        var count = await query.CountAsync(ct);
        if (count == 0) return null;

        var soonest = await query.OrderBy(e => e.ExpiresAtUtc).Take(EvidenceLimit)
            .Select(e => new { e.TemplateTypeKey, e.ExpiresAtUtc })
            .ToListAsync(ct);

        return new AttentionItem
        {
            Kind = AttentionKind.PqcExceptionExpiring,
            Severity = AttentionSeverity.Warning,
            Count = count,
            Title = $"{count} PQC {Plural(count, "exception", "exceptions")} end within {PqcExceptionWarningDays} days",
            Explanation = "When an exception ends, requests it let through as a warning are refused again at the template's PQC stage, including ones already waiting for approval.",
            Evidence = soonest.Select(e => new AttentionEvidence
            {
                Label = e.TemplateTypeKey,
                Detail = $"Ends {AsUtc(e.ExpiresAtUtc).ToString("u", CultureInfo.InvariantCulture)}",
                Href = PqcExceptionsHref,
                OccurredAtUtc = AsUtc(e.ExpiresAtUtc)
            }).ToList(),
            ActionLabel = "Open PQC exceptions",
            ActionHref = PqcExceptionsHref
        };
    }

    private async Task<AttentionItem?> IssuerRevokedAsync(CancellationToken ct)
    {
        var retired = await db.Issuers.AsNoTracking()
            .Where(i => i.Status == IssuerStatus.Retired && i.RetiredAtUtc != null && i.SerialNumber != null && i.ParentIssuerId != null)
            .ToListAsync(ct);
        if (retired.Count == 0) return null;

        var parentIds = retired.Select(i => i.ParentIssuerId!.Value).Distinct().ToList();
        var parents = await db.Issuers.AsNoTracking()
            .Where(i => parentIds.Contains(i.Id) && i.UploadedCrlDer != null)
            .ToDictionaryAsync(i => i.Id, i => i.UploadedCrlDer!, ct);

        var revokedByParent = new Dictionary<IssuerId, HashSet<Org.BouncyCastle.Math.BigInteger>>();
        foreach (var (parentId, der) in parents)
        {
            try
            {
                var crl = new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(der);
                revokedByParent[parentId] = (crl?.GetRevokedCertificates() ?? new HashSet<Org.BouncyCastle.X509.X509CrlEntry>())
                    .Select(e => e.SerialNumber).ToHashSet();
            }
            catch (Exception ex) when (ex is IOException or Org.BouncyCastle.Security.Certificates.CrlException or ArgumentException)
            {
                // An unparseable stored CRL cannot prove anything; RootCrlExpiring covers stale ones.
            }
        }

        var revoked = retired.Where(i =>
                revokedByParent.TryGetValue(i.ParentIssuerId!.Value, out var serials) &&
                serials.Contains(new Org.BouncyCastle.Math.BigInteger(i.SerialNumber!, 16)))
            .OrderByDescending(i => i.RetiredAtUtc)
            .ToList();
        if (revoked.Count == 0) return null;

        return new AttentionItem
        {
            Kind = AttentionKind.IssuerRevoked,
            Severity = AttentionSeverity.Critical,
            Count = revoked.Count,
            Title = $"{revoked.Count} {Plural(revoked.Count, "issuer was", "issuers were")} revoked by {Plural(revoked.Count, "its", "their")} parent",
            Explanation = "The parent's CRL lists these issuers as revoked, so certificates they signed no longer validate for clients that check revocation. They were retired; reissue what they signed under another issuer.",
            Evidence = revoked.Take(EvidenceLimit).Select(i => new AttentionEvidence
            {
                Label = i.Name,
                Detail = $"Serial {i.SerialNumber} listed on the parent's CRL",
                Href = IssuersHref,
                OccurredAtUtc = AsUtc(i.RetiredAtUtc!.Value)
            }).ToList(),
            ActionLabel = "Open issuers",
            ActionHref = IssuersHref
        };
    }

    internal static DateTime AsUtc(DateTime value) => value.Kind switch
    {
        DateTimeKind.Utc => value,
        DateTimeKind.Local => value.ToUniversalTime(),
        _ => DateTime.SpecifyKind(value, DateTimeKind.Utc)
    };

    internal static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max] + "…";

    internal static string Plural(int count, string one, string many) => count == 1 ? one : many;

    internal static string FormatDays(int days) => $"{days} {Plural(days, "day", "days")}";

    internal static string FormatHours(int hours) =>
        hours % 24 == 0 ? FormatDays(hours / 24) : $"{hours} {Plural(hours, "hour", "hours")}";

    internal static string FormatAge(TimeSpan age)
    {
        if (age.TotalHours >= 48)
            return FormatDays((int)Math.Floor(age.TotalDays));

        var hours = Math.Max(0, (int)Math.Floor(age.TotalHours));
        return $"{hours.ToString(CultureInfo.InvariantCulture)} {Plural(hours, "hour", "hours")}";
    }
}
