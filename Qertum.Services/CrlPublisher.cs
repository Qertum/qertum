using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services.Issuers;

namespace Qertum.Services;

/// <summary>A freshly published full CRL.</summary>
public sealed record PublishedCrl(byte[] Bytes, long CrlNumber, DateTime ThisUpdateUtc);

/// <summary>
/// The only way a full CRL is published: <c>/crl</c> on a cache miss, <c>POST /v1/crl/reset-base</c>
/// and the scheduled <c>CrlRefresh</c> background job all call <see cref="PublishFullCrlAsync"/>.
/// </summary>
public sealed class CrlPublisher(
    ICertificateRequestService service,
    Issuers.IIssuerRegistry issuers,
    Issuers.IssuerCrlState crlState,
    IDistributedCache cache,
    ILogger<CrlPublisher>? logger = null,
    TimeProvider? timeProvider = null)
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly ILogger _logger = logger ?? NullLogger<CrlPublisher>.Instance;

    /// <summary>A stored <c>CrlValidityHours</c> of zero or less means the 24-hour default.</summary>
    public static int EffectiveValidityHours(int configuredHours) => configuredHours > 0 ? configuredHours : 24;

    /// <summary>Publishes the full CRL served at the unprefixed <c>/crl</c> (see <see cref="Issuers.IssuerRegistryExtensions.ForUnscopedCrlAsync"/>).</summary>
    public async Task<PublishedCrl> PublishFullCrlAsync(CancellationToken cancellationToken = default) =>
        await PublishFullCrlAsync(await issuers.ForUnscopedCrlAsync(cancellationToken) ?? throw new CaNotInitializedException(),
            cancellationToken);

    /// <summary>
    /// Builds a fresh full CRL for <paramref name="issuer"/>, caches it, and records it as that
    /// issuer's new delta base — unconditionally, with no cache-hit shortcut.
    /// </summary>
    public Task<PublishedCrl> PublishFullCrlAsync(Issuers.IssuerHandle issuer, CancellationToken cancellationToken = default) =>
        PublishFullCrlAsync(issuer, tolerateCacheFailure: false, cancellationToken);

    /// <summary>
    /// As <see cref="PublishFullCrlAsync(Issuers.IssuerHandle, CancellationToken)"/>. With
    /// <paramref name="tolerateCacheFailure"/> a cache that cannot be written or cleared is logged and
    /// ignored, which is what a CRL request needs while Redis is down: the CRL is still built, recorded as
    /// the delta base and returned. The scheduled refresh and <c>reset-base</c> leave it false: their job is
    /// to repopulate the cache, so a failure must fail them and let the job retry.
    /// </summary>
    /// <param name="issuer">The issuer to publish for.</param>
    /// <param name="tolerateCacheFailure">Whether to carry on when the cache fails.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public async Task<PublishedCrl> PublishFullCrlAsync(Issuers.IssuerHandle issuer, bool tolerateCacheFailure, CancellationToken cancellationToken = default)
    {
        if (!issuer.CanSignRevocation)
            throw new InvalidOperationException($"Issuer '{issuer.Issuer.Name}' cannot sign a CRL (status {issuer.Issuer.Status}).");

        var settings = await service.GetSettingsAsync(cancellationToken);
        // Unpaged on purpose: a revoked certificate left out of the CRL is one every relying
        // party still treats as valid.
        var revoked = await service.GetAllRevokedForCrlAsync(issuer.Scope, cancellationToken);

        // Claimed only once the CRL is actually about to be built, so a failed request does not burn
        // a number.
        var crlNumber = await crlState.ClaimNextCrlNumberAsync(issuer.Issuer, cancellationToken);
        var thisUpdate = _clock.GetUtcNow().UtcDateTime;
        var crlBytes = issuer.Generator!.GenerateCrl(revoked, settings, crlNumber, thisUpdate,
            Issuers.IssuerUrls.For(issuer.Issuer, settings));
        var cacheEntry = new DistributedCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromHours(EffectiveValidityHours(settings.CrlValidityHours))
        };
        if (tolerateCacheFailure)
            await cache.TrySetAsync(CrlCache.KeyFor(issuer.Issuer), crlBytes, cacheEntry, _logger, cancellationToken);
        else
            await cache.SetAsync(CrlCache.KeyFor(issuer.Issuer), crlBytes, cacheEntry, cancellationToken);

        // This full CRL is the new delta base. Record it, and drop any cached delta computed
        // against the previous base — it is now relative to a base number the server would no
        // longer vouch for.
        await crlState.RecordBaseCrlAsync(issuer.Issuer, crlNumber, thisUpdate, cancellationToken);
        if (tolerateCacheFailure)
            await cache.TryRemoveAsync(CrlCache.DeltaKeyFor(issuer.Issuer), _logger, cancellationToken);
        else
            await cache.RemoveAsync(CrlCache.DeltaKeyFor(issuer.Issuer), cancellationToken);

        return new PublishedCrl(crlBytes, crlNumber, thisUpdate);
    }
}
