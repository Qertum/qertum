using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Crl;

/// <summary>
/// The CRL number was incremented and read back in two statements, so concurrent publishers could read the same final
/// value and sign different CRLs with one number, and a slower publisher could then overwrite a newer CRL in the
/// cache and as the delta base; and every concurrent cache miss on the anonymous CRL routes built its own CRL
/// (AI Scan, 1.0.0-rc6). Runs on a file database, where SQLite's write lock is what serializes publishers.
/// </summary>
public sealed class CrlConcurrencyTests : IDisposable
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private readonly string _path = Path.Combine(Path.GetTempPath(), $"qertum-crl-{Guid.NewGuid():N}.db");
    private readonly DbContextOptions<CertificateRequestDbContext> _options;
    private readonly Issuer _issuer = new() { Name = "Issuing", Kind = IssuerKind.Intermediate, KeyCustody = IssuerKeyCustody.Online, Status = IssuerStatus.Active };

    public CrlConcurrencyTests()
    {
        _options = new DbContextOptionsBuilder<CertificateRequestDbContext>().UseSqlite($"Data Source={_path};Pooling=False").Options;
        using var db = Context();
        db.Database.EnsureCreated();
        db.Issuers.Add(_issuer);
        db.SaveChanges();
    }

    private CertificateRequestDbContext Context() => new(_options, new EphemeralDataProtectionProvider());

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();
        File.Delete(_path);
    }

    [Fact]
    public async Task ConcurrentClaims_NeverReturnTheSameNumber()
    {
        const int publishers = 24;
        var claimed = await Task.WhenAll(Enumerable.Range(0, publishers).Select(_ => Task.Run(async () =>
        {
            await using var db = Context();
            return await new IssuerCrlState(db, null!).ClaimNextCrlNumberAsync(_issuer, Ct);
        }, Ct)));

        Assert.Equal(publishers, claimed.Distinct().Count());
        Assert.Equal(Enumerable.Range(1, publishers).Select(i => (long)i), claimed.Order());
    }

    [Fact]
    public async Task AnOlderCrl_NeverReplacesTheRecordedNewerOne()
    {
        var published = new List<long>();
        await using (var db = Context())
        {
            var state = new IssuerCrlState(db, null!);
            Assert.True(await state.RecordBaseCrlIfNewerAsync(_issuer, 6, DateTime.UtcNow, () => { published.Add(6); return Task.CompletedTask; }, Ct));
            // The publisher that claimed 5 finishes last: nothing of it may be recorded or cached.
            Assert.False(await state.RecordBaseCrlIfNewerAsync(_issuer, 5, DateTime.UtcNow, () => { published.Add(5); return Task.CompletedTask; }, Ct));
        }

        Assert.Equal([6L], published);
        await using var check = Context();
        Assert.Equal(6, (await check.Issuers.AsNoTracking().SingleAsync(i => i.Id == _issuer.Id, Ct)).BaseCrlNumber);
    }

    [Fact]
    public async Task AFailedCacheWrite_LeavesTheBaseUnrecorded()
    {
        await using (var db = Context())
        {
            await Assert.ThrowsAsync<InvalidOperationException>(() => new IssuerCrlState(db, null!).RecordBaseCrlIfNewerAsync(
                _issuer, 3, DateTime.UtcNow, () => throw new InvalidOperationException("cache down"), Ct));
        }

        await using var check = Context();
        Assert.Null((await check.Issuers.AsNoTracking().SingleAsync(i => i.Id == _issuer.Id, Ct)).BaseCrlNumber);
    }

    [Fact]
    public async Task ConcurrentCacheMisses_BuildTheCrlOnce()
    {
        var gate = new CrlBuildGate();
        var builds = 0;
        var release = new TaskCompletionSource();
        async Task<byte[]> Build()
        {
            Interlocked.Increment(ref builds);
            await release.Task;
            return [1, 2, 3];
        }

        var requests = Enumerable.Range(0, 20)
            .Select(_ => gate.GetOrBuildAsync("crl:issuer", () => Task.FromResult<byte[]?>(null), Build, Ct))
            .ToList();
        await Task.Delay(100, Ct);
        release.SetResult();
        var results = await Task.WhenAll(requests);

        Assert.Equal(1, builds);
        Assert.All(results, r => Assert.Equal(new byte[] { 1, 2, 3 }, r));
    }

    [Fact]
    public async Task ACrlBuiltBeforeARequestStarted_IsNotReusedFromMemory()
    {
        // After a revocation the cache entry is evicted; the next request must build, not reuse an older build.
        var gate = new CrlBuildGate();
        await gate.GetOrBuildAsync("crl:issuer", () => Task.FromResult<byte[]?>(null), () => Task.FromResult(new byte[] { 1 }), Ct);

        var second = await gate.GetOrBuildAsync("crl:issuer", () => Task.FromResult<byte[]?>(null), () => Task.FromResult(new byte[] { 2 }), Ct);

        Assert.Equal(new byte[] { 2 }, second);
    }
}
