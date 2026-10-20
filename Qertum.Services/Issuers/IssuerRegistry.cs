using System.Collections.Concurrent;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Issuers;

/// <summary>
/// Every issuer this server knows, with a <see cref="CertificateGenerator"/> for each online one.
/// Rows are cached per host and reloaded when the shared stamp changes (every issuer mutation calls
/// <see cref="InvalidateAsync"/>) or after <see cref="MaxAge"/>, so make-default and retire reach
/// every host within seconds. The legacy issuer signs through the DI <see cref="ICertificateGenerator"/>
/// (the pre-hierarchy files); while the table is empty that generator is bootstrapped into a row,
/// and when even that fails a synthetic handle keeps single-CA behaviour.
/// </summary>
public sealed class IssuerRegistry(
    IServiceScopeFactory scopes,
    ICertificateGenerator legacy,
    IssuerStorage storage,
    IDataProtectionProvider dataProtection,
    IDistributedCache cache,
    ILoggerFactory loggerFactory,
    TimeProvider? timeProvider = null) : IIssuerRegistry
{
    public const string VersionCacheKey = "issuers:version";
    internal static readonly TimeSpan MaxAge = TimeSpan.FromSeconds(30);

    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;
    private readonly ILogger _logger = loggerFactory.CreateLogger<IssuerRegistry>();
    private readonly SemaphoreSlim _gate = new(1, 1);
    private Snapshot? _snapshot;
    private string? _lastStamp;
    private bool _legacyUnregistrable;

    private sealed record Snapshot(string? Stamp, DateTime LoadedAtUtc, IReadOnlyList<Issuer> Rows,
        ConcurrentDictionary<IssuerId, ICertificateGenerator?> Generators);

    public async Task<IReadOnlyList<Issuer>> GetAllAsync(CancellationToken ct = default) =>
        (await CurrentAsync(ct)).Rows;

    public async Task<IssuerHandle?> GetDefaultAsync(CancellationToken ct = default)
    {
        var snapshot = await CurrentAsync(ct);
        var row = snapshot.Rows.FirstOrDefault(i => i.IsDefault);
        if (row is not null) return Handle(snapshot, row);
        return snapshot.Rows.Count == 0 ? SyntheticLegacy() : null;
    }

    public async Task<IssuerHandle?> GetAsync(IssuerId id, CancellationToken ct = default)
    {
        var snapshot = await CurrentAsync(ct);
        var row = snapshot.Rows.FirstOrDefault(i => i.Id == id);
        return row is null ? null : Handle(snapshot, row);
    }

    public async Task<IssuerHandle?> ForRequestAsync(CertificateRequest request, CancellationToken ct = default)
    {
        if (request.IssuerId is { } id) return await GetAsync(id, ct);
        var snapshot = await CurrentAsync(ct);
        var row = snapshot.Rows.FirstOrDefault(i => i.LegacyFiles);
        if (row is not null) return Handle(snapshot, row);
        return snapshot.Rows.Count == 0 ? SyntheticLegacy() : null;
    }

    public async Task<IssuerHandle> ForIssuanceAsync(CertificateTemplate? template, CancellationToken ct = default)
    {
        IssuerHandle? handle;
        if (template?.IssuerId is { } pinned)
        {
            handle = await GetAsync(pinned, ct)
                     ?? throw new CaNotInitializedException($"Template '{template.TypeKey}' is pinned to an issuer that does not exist.");
        }
        else
        {
            handle = await GetDefaultAsync(ct) ?? throw new CaNotInitializedException();
        }

        if (!handle.CanIssue)
            throw new IssuerNotActiveException(handle.Issuer.Name, handle.Issuer.Status);
        return handle;
    }

    public async Task<IReadOnlyList<string>> ChainForAsync(IssuerId id, CancellationToken ct = default)
    {
        var snapshot = await CurrentAsync(ct);
        var chain = new List<string>();
        var current = snapshot.Rows.FirstOrDefault(i => i.Id == id);
        if (current is null && id.Value == Guid.Empty && snapshot.Rows.Count == 0 && legacy.IsInitialized)
            return [legacy.GetCaCertificatePem()];

        // Bounded: a malformed parent link must not loop forever.
        for (var depth = 0; current is not null && depth < 16; depth++)
        {
            if (current.CertificatePem is not null) chain.Add(current.CertificatePem);
            if (current.ParentIssuerId is not { } parentId) break;
            current = snapshot.Rows.FirstOrDefault(i => i.Id == parentId);
        }
        return chain;
    }

    public async Task<IssuerHandle?> MatchOcspIssuerAsync(byte[] derRequest, CancellationToken ct = default)
    {
        var first = new Org.BouncyCastle.Ocsp.OcspReq(derRequest).GetRequestList().FirstOrDefault()?.GetCertID();
        if (first is null) return null;

        var snapshot = await CurrentAsync(ct);
        IEnumerable<IssuerHandle> candidates = snapshot.Rows.Count == 0
            ? SyntheticLegacy() is { } synthetic ? [synthetic] : []
            : snapshot.Rows.Select(r => Handle(snapshot, r));
        foreach (var handle in candidates.Where(h => h.CanSignRevocation))
        {
            var pem = handle.Issuer.CertificatePem ?? handle.Generator!.GetCaCertificatePem();
            Org.BouncyCastle.X509.X509Certificate? certificate;
            try { certificate = Crypto.QertumKeyCodec.ReadCertificatePem(pem); }
            catch (IOException) { continue; }
            if (certificate is not null && first.MatchesIssuer(certificate))
                return handle;
        }
        return null;
    }

    public async Task<IReadOnlyList<Issuer>> PathForAsync(IssuerId id, CancellationToken ct = default)
    {
        var snapshot = await CurrentAsync(ct);
        var path = new List<Issuer>();
        var current = snapshot.Rows.FirstOrDefault(i => i.Id == id);
        // Bounded: a malformed parent link must not loop forever.
        for (var depth = 0; current is not null && depth < 16; depth++)
        {
            path.Add(current);
            current = current.ParentIssuerId is { } parent ? snapshot.Rows.FirstOrDefault(i => i.Id == parent) : null;
        }
        return path;
    }

    public async Task InvalidateAsync(CancellationToken ct = default)
    {
        var stamp = Guid.NewGuid().ToString("N");
        try
        {
            await cache.SetStringAsync(VersionCacheKey, stamp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not publish the issuer stamp; other hosts reload within {MaxAge}.", MaxAge);
        }
        _snapshot = null;
    }

    private async Task<Snapshot> CurrentAsync(CancellationToken ct)
    {
        var stamp = await ReadStampAsync(ct);
        var now = _clock.GetUtcNow().UtcDateTime;
        var snapshot = _snapshot;
        if (IsFresh(snapshot, stamp, now))
            return snapshot!;

        await _gate.WaitAsync(ct);
        try
        {
            snapshot = _snapshot;
            if (IsFresh(snapshot, stamp, now))
                return snapshot!;

            await using var scope = scopes.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            try
            {
                await IssuerBootstrap.EnsureLegacyIssuerAsync(db, legacy,
                    scope.ServiceProvider.GetService<IAuditLogService>(), _clock, ct);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // A stub generator or an unparseable ca.pem: SyntheticLegacy keeps single-CA behaviour.
                // Remembered so an empty table does not retry (and log) on every call.
                _legacyUnregistrable = true;
                _logger.LogWarning(ex, "Could not register the legacy CA as an issuer; using it unregistered.");
            }

            var rows = await db.Issuers.AsNoTracking().OrderBy(i => i.CreatedAtUtc).ToListAsync(ct);
            SweepDestroyedKeys(rows);
            _snapshot = new Snapshot(stamp, now, rows, new ConcurrentDictionary<IssuerId, ICertificateGenerator?>());
            return _snapshot;
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// An empty snapshot goes stale the moment the legacy CA files appear: onboarding writes them in
    /// another process, and "no CA" must not be served from cache after that.
    /// </summary>
    private bool IsFresh(Snapshot? snapshot, string? stamp, DateTime now) =>
        snapshot is not null && snapshot.Stamp == stamp && now - snapshot.LoadedAtUtc < MaxAge &&
        !(snapshot.Rows.Count == 0 && legacy.IsInitialized && !_legacyUnregistrable);

    private async Task<string?> ReadStampAsync(CancellationToken ct)
    {
        try
        {
            var stamp = await cache.GetStringAsync(VersionCacheKey, ct);
            if (!string.IsNullOrEmpty(stamp)) _lastStamp = stamp;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Issuer stamp unavailable; using the last known value.");
        }
        return _lastStamp;
    }

    private IssuerHandle Handle(Snapshot snapshot, Issuer row) =>
        new(row, snapshot.Generators.GetOrAdd(row.Id, _ => CreateGenerator(row)));

    private ICertificateGenerator? CreateGenerator(Issuer row)
    {
        if (row.KeyCustody != IssuerKeyCustody.Online || row.CertificatePem is null ||
            row.Status is not (IssuerStatus.Active or IssuerStatus.Retired))
            return null;

        if (row.LegacyFiles)
            return legacy.IsInitialized ? legacy : null;

        var generator = new CertificateGenerator(dataProtection, storage.OptionsFor(row),
            loggerFactory.CreateLogger<CertificateGenerator>(), timeProvider: _clock);
        if (generator.IsInitialized) return generator;

        _logger.LogError("Issuer {IssuerId} ({IssuerName}) is online but its key or certificate file is missing under {Directory}.",
            row.Id, row.Name, storage.DirectoryFor(row));
        return null;
    }

    private IssuerHandle? SyntheticLegacy()
    {
        if (!legacy.IsInitialized) return null;
        return new IssuerHandle(new Issuer
        {
            Id = new IssuerId(Guid.Empty),
            Name = "Default CA",
            Kind = IssuerKind.Root,
            KeyCustody = IssuerKeyCustody.Online,
            Status = IssuerStatus.Active,
            IsDefault = true,
            LegacyFiles = true
        }, legacy);
    }

    private void SweepDestroyedKeys(IEnumerable<Issuer> rows)
    {
        foreach (var row in rows.Where(r => r.Status is IssuerStatus.Destroyed or IssuerStatus.Archived))
        {
            try
            {
                if (storage.HasKeyFile(row) || File.Exists(storage.CertificatePath(row)))
                {
                    storage.DeleteFiles(row);
                    _logger.LogWarning("Deleted leftover key files of {Status} issuer {IssuerId} ({IssuerName}).",
                        row.Status, row.Id, row.Name);
                }
            }
            catch (IOException ex)
            {
                _logger.LogError(ex, "Could not delete leftover key files of issuer {IssuerId}.", row.Id);
            }
        }
    }
}
