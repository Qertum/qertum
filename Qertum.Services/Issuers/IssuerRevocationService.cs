using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

/// <summary>
/// The backstop for a revoked CA certificate: when the certificate an issuer stands on is revoked, the
/// issuer (and, in <see cref="RevokedIssuerMode.HardStop"/>, everything below it) stops issuing at once.
/// Retiring keeps CRL and OCSP answers for what it signed. Idempotent: run when the revocation is queued and
/// again when it is finalized, so a failure between the two cannot leave a revoked root signing.
/// </summary>
public sealed class IssuerRevocationService(
    CertificateRequestDbContext db,
    IIssuerRegistry issuers,
    IAuditLogService audit,
    IWebhookService webhooks,
    TimeProvider? timeProvider = null)
{
    private const int MaxDepth = 16; // a malformed parent link must not loop forever
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <summary>
    /// Takes the issuer that <paramref name="revoked"/> belongs to out of service, if it is one. Does nothing for
    /// an ordinary certificate, an issuer already handled, or one that is Archived or Destroyed.
    /// </summary>
    public async Task OnCertificateRevokedAsync(CertificateRequest revoked, string performedBy, CancellationToken ct)
    {
        var issuer = await FindIssuerOfAsync(revoked, ct);
        if (issuer is null || issuer.Status is IssuerStatus.Archived or IssuerStatus.Destroyed) return;

        var mode = (await db.Settings.AsNoTracking().SingleOrDefaultAsync(s => s.Id == 1, ct))?.RevokedIssuerMode
                   ?? RevokedIssuerMode.HardStop;
        var now = _clock.GetUtcNow().UtcDateTime;

        var targets = new List<Issuer> { issuer };
        if (mode == RevokedIssuerMode.HardStop)
            targets.AddRange(await DescendantsAsync(issuer, ct));

        var changed = new List<Issuer>();
        foreach (var target in targets)
        {
            if (target.Status is IssuerStatus.Archived or IssuerStatus.Destroyed) continue;
            if (target.RevokedAtUtc is not null && target.Status == IssuerStatus.Retired && !target.IsDefault) continue;

            target.RevokedAtUtc ??= now;
            target.IsDefault = false;
            if (target.Status is IssuerStatus.Active or IssuerStatus.PendingCertificate)
            {
                target.Status = IssuerStatus.Retired;
                target.RetiredAtUtc ??= now;
            }
            changed.Add(target);
        }
        if (changed.Count == 0) return;

        await db.SaveChangesAsync(ct);

        await audit.LogAsync("IssuerRevokedByCertificate", performedBy, (Guid)issuer.Id, issuer.Name,
            $"Its certificate was revoked ({mode}). Retired and no longer issuing: {string.Join(", ", changed.Select(c => $"'{c.Name}'"))}. " +
            "Still answers CRL and OCSP for what it signed.", ct);
        foreach (var target in changed)
            await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRetired, target, performedBy), ct);
        await issuers.InvalidateAsync(ct);
    }

    /// <summary>
    /// The issuer whose own certificate <paramref name="revoked"/> is: the root a RootCA request created, or an
    /// installed subordinate whose serial was signed by the request's issuer. Null for anything else.
    /// </summary>
    private async Task<Issuer?> FindIssuerOfAsync(CertificateRequest revoked, CancellationToken ct)
    {
        if (revoked.Type == WellKnownCertificateTypes.RootCa)
            return await IssuerQueries.RootIssuerOfAsync(db, revoked, ct);

        if (string.IsNullOrEmpty(revoked.SerialNumber)) return null;
        var parentId = revoked.IssuerId ?? (await db.Issuers.AsNoTracking().FirstOrDefaultAsync(i => i.LegacyFiles, ct))?.Id;
        return parentId is null
            ? null
            : await db.Issuers.FirstOrDefaultAsync(i => i.SerialNumber == revoked.SerialNumber && i.ParentIssuerId == parentId, ct);
    }

    private async Task<List<Issuer>> DescendantsAsync(Issuer root, CancellationToken ct)
    {
        var all = await db.Issuers.Where(i => i.ParentIssuerId != null).ToListAsync(ct);
        var found = new List<Issuer>();
        var frontier = new List<IssuerId> { root.Id };
        for (var depth = 0; depth < MaxDepth && frontier.Count > 0; depth++)
        {
            var next = all.Where(i => frontier.Contains(i.ParentIssuerId!.Value) && found.All(f => f.Id != i.Id)).ToList();
            found.AddRange(next);
            frontier = next.Select(i => i.Id).ToList();
        }
        return found;
    }
}
