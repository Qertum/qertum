using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Services.BackgroundJobs;

namespace Qertum.QueueConsumer;

/// <summary>
/// The <c>Acme:ExpiryCleanup</c> section: the periodic sweep that removes ACME orders which have aged out.
/// Read by QueueConsumer, which runs the sweep as a background job; AcmeService only serves the protocol.
/// </summary>
public sealed class AcmeExpiryCleanupOptions
{
    public const string SectionName = "Acme:ExpiryCleanup";

    public bool Enabled { get; set; } = true;

    /// <summary>How long to wait between sweeps.</summary>
    public TimeSpan Interval { get; set; } = TimeSpan.FromHours(1);

    /// <summary>
    /// How long an order is kept after its expiry. Expiry alone already stops an order from being
    /// used; this grace period exists so a client polling a just-expired order still gets a
    /// coherent answer instead of a bare 404.
    /// </summary>
    public TimeSpan Retention { get; set; } = TimeSpan.FromDays(7);

    /// <summary>Maximum orders removed per sweep, so one pass cannot lock the database for long.</summary>
    public int BatchSize { get; set; } = 500;
}

/// <summary>
/// Runs <see cref="WellKnownJobTypes.AcmeExpiryCleanup"/>: deletes one batch of ACME orders past their
/// expiry plus retention, along with the authorizations and challenges hanging off them. Expiry
/// enforcement lives in the endpoints and is not this job's concern — nothing here changes whether a
/// certificate can be issued, it only stops the tables growing without bound.
/// </summary>
internal sealed class AcmeExpiryCleanupJobHandler(
    CertificateRequestDbContext db,
    IOptions<AcmeExpiryCleanupOptions> options,
    ILogger<AcmeExpiryCleanupJobHandler> logger,
    TimeProvider? timeProvider = null) : IBackgroundJobHandler
{
    public const string ConcurrencyKey = "acme-expiry-cleanup";
    public const string RequestedBy = "acme-expiry-cleanup-scheduler";

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    /// <summary>Same schedule as the timer it replaced in AcmeService: at start, then every <c>Interval</c>.</summary>
    public static IntervalJob Schedule(AcmeExpiryCleanupOptions options) => new(
        WellKnownJobTypes.AcmeExpiryCleanup, ConcurrencyKey, RequestedBy,
        InitialDelay: TimeSpan.Zero, Interval: options.Interval, Enabled: options.Enabled);

    public string JobType => WellKnownJobTypes.AcmeExpiryCleanup;

    public async Task<string?> HandleAsync(BackgroundJob job, CancellationToken cancellationToken)
    {
        var removed = await SweepAsync(cancellationToken);
        if (removed > 0)
            logger.LogInformation("ACME expiry cleanup removed {OrderCount} expired orders.", removed);
        return $"orders={removed}";
    }

    /// <summary>Removes one batch of aged-out orders. Returns how many orders were deleted.</summary>
    internal async Task<int> SweepAsync(CancellationToken ct)
    {
        var cutoff = _clock.GetUtcNow().UtcDateTime - options.Value.Retention;

        var orderIds = await db.AcmeOrders
            .Where(o => o.ExpiresAtUtc <= cutoff)
            .OrderBy(o => o.ExpiresAtUtc)
            .Take(options.Value.BatchSize)
            .Select(o => o.Id)
            .ToListAsync(ct);

        if (orderIds.Count == 0) return 0;

        // Deleted child-first rather than leaning on cascade: ExecuteDeleteAsync issues raw DELETEs
        // that bypass the change tracker, so the cascade would have to come from the database's own
        // foreign keys — which SQLite only enforces when the connection has foreign_keys enabled.
        // Doing it in order is correct regardless of that pragma.
        var authorizationIds = await db.AcmeAuthorizations
            .Where(a => orderIds.Contains(a.OrderId))
            .Select(a => a.Id)
            .ToListAsync(ct);

        await db.AcmeChallenges
            .Where(c => authorizationIds.Contains(c.AuthorizationId))
            .ExecuteDeleteAsync(ct);

        await db.AcmeAuthorizations
            .Where(a => orderIds.Contains(a.OrderId))
            .ExecuteDeleteAsync(ct);

        // The issued CertificateRequest rows an order points at are deliberately left alone: they
        // are the certificate record, audited and surfaced in the UI, and outlive the ACME order
        // that happened to produce them.
        return await db.AcmeOrders
            .Where(o => orderIds.Contains(o.Id))
            .ExecuteDeleteAsync(ct);
    }
}
