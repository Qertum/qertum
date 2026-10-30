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

    /// <summary>
    /// Registers <paramref name="newDefault"/> as the active default issuer when none exists (every earlier one was
    /// taken out of service by a revoked certificate). Nothing is destroyed: the revoked issuers keep their rows
    /// and files so CRL and OCSP keep answering for what they signed.
    /// </summary>
    public async Task RegisterDefaultAsync(Issuer newDefault, string performedBy, CancellationToken ct)
    {
        newDefault.IsDefault = true;
        newDefault.Status = IssuerStatus.Active;
        newDefault.ActivatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        db.Issuers.Add(newDefault);
        await db.SaveChangesAsync(ct);

        await audit.LogAsync("IssuerRegistered", performedBy, (Guid)newDefault.Id, newDefault.Name,
            "Registered as the new default after the previous issuers were taken out of service by a revoked certificate.", ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRegistered, newDefault, performedBy), ct);
        await issuers.InvalidateAsync(ct);
    }

    /// <summary>
    /// A renewed root: <paramref name="replacement"/> (a new key under the same name) becomes the active default
    /// and takes over the template pins of <paramref name="renewed"/>. A live <paramref name="renewed"/> is
    /// retired, never destroyed: what it signed stays checkable through its CRL and OCSP. A revoked one is
    /// already retired and stays as it is.
    /// </summary>
    public async Task RenewRootAsync(Issuer renewed, Issuer replacement, string performedBy, CancellationToken ct)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        var retiredNow = false;
        int pinsMoved;
        await using (var transaction = await db.Database.BeginTransactionAsync(ct))
        {
            var old = await db.Issuers.SingleAsync(i => i.Id == renewed.Id, ct);
            if (old.IsDefault || old.Status == IssuerStatus.Active)
            {
                retiredNow = old.Status == IssuerStatus.Active;
                old.IsDefault = false;
                old.Status = IssuerStatus.Retired;
                old.RetiredAtUtc ??= now;
                // Own SaveChanges: SQLite checks the filtered unique index per statement.
                await db.SaveChangesAsync(ct);
            }

            replacement.IsDefault = true;
            replacement.Status = IssuerStatus.Active;
            replacement.ActivatedAtUtc = now;
            db.Issuers.Add(replacement);
            await db.SaveChangesAsync(ct);

            pinsMoved = await db.CertificateTemplates.Where(t => t.IssuerId == renewed.Id)
                .ExecuteUpdateAsync(t => t.SetProperty(x => x.IssuerId, replacement.Id), ct);
            await transaction.CommitAsync(ct);
        }

        if (retiredNow)
        {
            await audit.LogAsync("IssuerRetired", performedBy, (Guid)renewed.Id, renewed.Name,
                $"Renewed as '{replacement.Name}' with a new key; issues nothing new, keeps answering CRL and OCSP.", ct);
            await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRetired, renewed, performedBy), ct);
        }
        await audit.LogAsync("IssuerRegistered", performedBy, (Guid)replacement.Id, replacement.Name,
            $"Registered as the new default by renewing '{renewed.Name}' with a new key"
            + (pinsMoved == 0 ? "." : $"; {pinsMoved} template pin(s) moved to it."), ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRegistered, replacement, performedBy), ct);
        await issuers.InvalidateAsync(ct);
    }

    /// <summary>What a renewal swap changed, for <see cref="AnnounceRenewalAsync"/> to report once it is committed.</summary>
    /// <param name="Old">The renewed issuer as it is after the swap.</param>
    /// <param name="Replacement">The replacement, now active.</param>
    /// <param name="RetiredNow">True when the old one was live and the swap retired it.</param>
    /// <param name="TakesDefault">True when the replacement took the default seat.</param>
    /// <param name="PinsMoved">Template pins moved from the old one to the replacement.</param>
    public sealed record IntermediateRenewal(Issuer Old, Issuer Replacement, bool RetiredNow, bool TakesDefault, int PinsMoved);

    /// <summary>
    /// A renewed intermediate, database part: <paramref name="replacement"/> (signed, a new key under the same name)
    /// becomes active, takes the default seat when the renewed one held it or nothing is default, and takes over its
    /// template pins. A live renewed issuer is retired, never destroyed; a revoked one stays as it is. Joins the
    /// caller's transaction when there is one (install), else opens its own. Writes no audit: the caller announces
    /// the result with <see cref="AnnounceRenewalAsync"/> after its own commit. The filtered unique index on
    /// <c>RenewalOfIssuerId</c> refuses a second replacement (<see cref="DbUpdateException"/>).
    /// </summary>
    public async Task<IntermediateRenewal> SwapRenewedIntermediateAsync(IssuerId renewedId, Issuer replacement, CancellationToken ct)
    {
        var now = _clock.GetUtcNow().UtcDateTime;
        await using var own = db.Database.CurrentTransaction is null ? await db.Database.BeginTransactionAsync(ct) : null;
        var old = await db.Issuers.SingleAsync(i => i.Id == renewedId, ct);
        var takesDefault = old.IsDefault || !await db.Issuers.AnyAsync(i => i.IsDefault && i.Id != replacement.Id, ct);
        var retiredNow = old.Status == IssuerStatus.Active;
        if (old.IsDefault || retiredNow)
        {
            old.IsDefault = false;
            if (retiredNow)
            {
                old.Status = IssuerStatus.Retired;
                old.RetiredAtUtc ??= now;
            }
            // Own SaveChanges: SQLite checks the filtered unique index per statement.
            await db.SaveChangesAsync(ct);
        }

        replacement.Status = IssuerStatus.Active;
        replacement.ActivatedAtUtc ??= now;
        replacement.IsDefault = takesDefault;
        if (db.Entry(replacement).State == EntityState.Detached) db.Issuers.Add(replacement);
        await db.SaveChangesAsync(ct);

        var pinsMoved = await db.CertificateTemplates.Where(t => t.IssuerId == renewedId)
            .ExecuteUpdateAsync(t => t.SetProperty(x => x.IssuerId, replacement.Id), ct);
        if (own is not null) await own.CommitAsync(ct);
        return new IntermediateRenewal(old, replacement, retiredNow, takesDefault, pinsMoved);
    }

    /// <summary>
    /// Audits and announces a committed renewal swap: <c>IssuerRetired</c> for a live old issuer (its payload carries
    /// its new status) and <c>IssuerCertificateInstalled</c> for the replacement, then invalidates the registry.
    /// <paramref name="signedBy"/> names the CA that signed the replacement.
    /// </summary>
    public async Task AnnounceRenewalAsync(IntermediateRenewal renewal, string signedBy, string performedBy, CancellationToken ct)
    {
        var (old, replacement) = (renewal.Old, renewal.Replacement);
        if (renewal.RetiredNow)
        {
            await audit.LogAsync("IssuerRetired", performedBy, (Guid)old.Id, old.Name,
                $"Renewed as '{replacement.Name}' with a new key; issues nothing new, keeps answering CRL and OCSP.", ct);
            await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerRetired, old, performedBy), ct);
        }
        await audit.LogAsync("IssuerCertificateInstalled", performedBy, (Guid)replacement.Id, replacement.Name,
            $"Renewal of '{old.Name}' with a new key, signed by '{signedBy}', valid to {replacement.ValidTo:yyyy-MM-dd}"
            + (renewal.TakesDefault ? ", now the default" : string.Empty)
            + (renewal.PinsMoved == 0 ? "." : $"; {renewal.PinsMoved} template pin(s) moved to it."), ct);
        await webhooks.EnqueueEventAsync(IssuerEvents.For(WellKnownWebhookEvents.IssuerCertificateInstalled, replacement, performedBy), ct);
        await issuers.InvalidateAsync(ct);
    }

    /// <summary>Unexpired certificates this issuer signed (Issued, PendingRevocation or Revoked, incl. paired PQC legs via the row) plus unexpired child CAs.</summary>
    public Task<int> UnexpiredCountAsync(Issuer issuer, CancellationToken ct) =>
        IssuerQueries.UnexpiredCountAsync(db, issuer, _clock.GetUtcNow().UtcDateTime, ct);
}
