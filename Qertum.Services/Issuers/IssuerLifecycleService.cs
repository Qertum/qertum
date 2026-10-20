using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Issuers;

/// <summary>Non-destructive rollover: make another issuer default, retire the old one, archive it once nothing it signed is still valid.</summary>
public sealed class IssuerLifecycleService(
    CertificateRequestDbContext db,
    IIssuerRegistry issuers,
    IssuerStorage storage,
    IAuditLogService audit,
    IWebhookService webhooks,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<IssuerOutcome<IssuerResponse>> MakeDefaultAsync(IssuerId id, string performedBy, CancellationToken ct)
    {
        var handle = await issuers.GetAsync(id, ct);
        if (handle is null) return IssuerOutcome<IssuerResponse>.NotFound($"Issuer {id} does not exist.");
        if (!handle.CanIssue || handle.Issuer.KeyCustody != IssuerKeyCustody.Online)
            return IssuerOutcome<IssuerResponse>.Conflict(
                $"Only an active online issuer with its key present can be the default; '{handle.Issuer.Name}' is {handle.Issuer.Status}, {handle.Issuer.KeyCustody}.");

        var issuer = await db.Issuers.SingleAsync(i => i.Id == id, ct);
        if (issuer.IsDefault) return IssuerOutcome<IssuerResponse>.Ok(IssuerMapping.ToResponse(issuer));

        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var previous = await db.Issuers.FirstOrDefaultAsync(i => i.IsDefault, ct);
        if (previous is not null)
        {
            previous.IsDefault = false;
            // Own SaveChanges: SQLite checks the filtered unique index per statement.
            await db.SaveChangesAsync(ct);
        }
        issuer.IsDefault = true;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);

        await audit.LogAsync("IssuerMadeDefault", performedBy, (Guid)issuer.Id, issuer.Name,
            previous is null ? "No previous default." : $"Previous default: '{previous.Name}' (stays active).", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerMadeDefault, issuer, performedBy), ct);
        await issuers.InvalidateAsync(ct);
        return IssuerOutcome<IssuerResponse>.Ok(IssuerMapping.ToResponse(issuer));
    }

    public async Task<IssuerOutcome<IssuerResponse>> RetireAsync(IssuerId id, string performedBy, CancellationToken ct)
    {
        var issuer = await db.Issuers.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (issuer is null) return IssuerOutcome<IssuerResponse>.NotFound($"Issuer {id} does not exist.");
        if (issuer.IsDefault)
            return IssuerOutcome<IssuerResponse>.Conflict($"'{issuer.Name}' is the default issuer; make another issuer default first.");
        if (issuer.Status != IssuerStatus.Active)
            return IssuerOutcome<IssuerResponse>.Conflict($"'{issuer.Name}' is {issuer.Status}; only an active issuer can be retired.");

        issuer.Status = IssuerStatus.Retired;
        issuer.RetiredAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);

        var pinned = await db.CertificateTemplates.Where(t => t.IssuerId == id).Select(t => t.TypeKey).ToListAsync(ct);
        await audit.LogAsync("IssuerRetired", performedBy, (Guid)issuer.Id, issuer.Name,
            pinned.Count == 0 ? "Issues nothing new; keeps answering CRL and OCSP."
                : $"Issues nothing new; templates still pinned to it will refuse issuance: {string.Join(", ", pinned)}.", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRetired, issuer, performedBy), ct);
        await issuers.InvalidateAsync(ct);
        return IssuerOutcome<IssuerResponse>.Ok(IssuerMapping.ToResponse(issuer));
    }

    public async Task<IssuerOutcome<IssuerResponse>> ArchiveAsync(IssuerId id, string performedBy, CancellationToken ct)
    {
        var issuer = await db.Issuers.FirstOrDefaultAsync(i => i.Id == id, ct);
        if (issuer is null) return IssuerOutcome<IssuerResponse>.NotFound($"Issuer {id} does not exist.");
        if (issuer.Status != IssuerStatus.Retired)
            return IssuerOutcome<IssuerResponse>.Conflict($"'{issuer.Name}' is {issuer.Status}; retire it before archiving.");

        var unexpired = await UnexpiredCountAsync(issuer, ct);
        if (unexpired > 0)
            return IssuerOutcome<IssuerResponse>.Conflict(
                $"'{issuer.Name}' still has {unexpired} unexpired certificate(s) that rely on its CRL and OCSP; archive after they expire.");

        issuer.Status = IssuerStatus.Archived;
        issuer.ArchivedAtUtc = _clock.GetUtcNow().UtcDateTime;
        await db.SaveChangesAsync(ct);
        storage.DeleteFiles(issuer); // the registry's sweep retries if this fails

        await audit.LogAsync("IssuerArchived", performedBy, (Guid)issuer.Id, issuer.Name, "Key deleted; row kept as history.", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerArchived, issuer, performedBy), ct);
        await issuers.InvalidateAsync(ct);
        return IssuerOutcome<IssuerResponse>.Ok(IssuerMapping.ToResponse(issuer));
    }

    /// <summary>The exact text a force replace of <paramref name="issuer"/> must carry in <c>confirm</c>.</summary>
    public static string ForceConfirmation(Issuer issuer) => "REPLACE " + issuer.Name;

    /// <summary>
    /// Force replace: <paramref name="replaced"/> becomes Destroyed and <paramref name="replacement"/> the
    /// active default in one transaction; then the old key files are deleted. Returns how many unexpired
    /// certificates the destroyed issuer signed — they can no longer be revoked.
    /// </summary>
    public async Task<int> ReplaceDefaultAsync(Issuer replaced, Issuer replacement, string performedBy, CancellationToken ct)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var affected = await UnexpiredCountAsync(replaced, ct);

        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            var old = await db.Issuers.SingleAsync(i => i.Id == replaced.Id, ct);
            old.IsDefault = false;
            old.Status = IssuerStatus.Destroyed;
            old.DestroyedAtUtc = now;
            // Own SaveChanges: SQLite checks the filtered unique index per statement.
            await db.SaveChangesAsync(ct);

            replacement.IsDefault = true;
            replacement.Status = IssuerStatus.Active;
            replacement.ActivatedAtUtc = now;
            db.Issuers.Add(replacement);
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
        }

        replaced.IsDefault = false;
        replaced.Status = IssuerStatus.Destroyed;
        replaced.DestroyedAtUtc = now;

        // After the commit: a crash here leaves the key on disk with the row Destroyed, and the
        // registry's sweep deletes it on the next load.
        try { storage.DeleteFiles(replaced); }
        catch (IOException) { /* swept on next registry load */ }

        await audit.LogAsync("IssuerDestroyed", performedBy, (Guid)replaced.Id, replaced.Name,
            $"Force-replaced by '{replacement.Name}'. Key and certificate deleted; {affected} unexpired certificate(s) it signed can no longer be revoked.", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerDestroyed, replaced, performedBy, affected), ct);
        await audit.LogAsync("IssuerRegistered", performedBy, (Guid)replacement.Id, replacement.Name,
            "Registered as the new default by a force replace.", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRegistered, replacement, performedBy), ct);
        await issuers.InvalidateAsync(ct);
        return affected;
    }

    /// <summary>Unexpired certificates this issuer signed (Issued, PendingRevocation or Revoked, incl. paired PQC legs via the row) plus unexpired child CAs.</summary>
    public Task<int> UnexpiredCountAsync(Issuer issuer, CancellationToken ct) =>
        IssuerQueries.UnexpiredCountAsync(db, issuer, _clock.GetUtcNow().UtcDateTime, ct);
}
