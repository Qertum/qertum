using System.Reflection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Issuers;
using Qertum.Tests.Issuers;

namespace Qertum.Tests.Crl;

public sealed class CrlPublicationIsolationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ARevocationCannotCommitBetweenTheFullCrlSnapshotAndPublication()
    {
        var clock = new FakeTimeProvider();
        await using var host = new IssuerApiHost(services => services.AddSingleton<TimeProvider>(clock));
        host.Kit.InitializeLegacy(algorithm: CertificateKeyAlgorithm.EcdsaP256);
        var serial = await host.SeedIssuedAsync(null, host.Kit.Legacy, revoked: false, Ct);
        using var scope = host.Factory.Services.CreateScope();
        var delayed = DispatchProxy.Create<ICertificateRequestService, PausedServiceCall>();
        var pause = (PausedServiceCall)(object)delayed;
        pause.Target = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
        var issuer = (await host.Registry.GetDefaultAsync(Ct))!;
        var state = scope.ServiceProvider.GetRequiredService<IssuerCrlState>();
        var publisher = new CrlPublisher(delayed, host.Registry, state, host.Kit.Cache, timeProvider: clock);
        var full = publisher.PublishFullCrlAsync(issuer, Ct);
        await pause.Captured.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var revoke = Task.Run(async () =>
        {
            using var worker = host.Factory.Services.CreateScope();
            started.SetResult();
            var db = worker.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var id = db.CertificateRequests.Single(r => r.SerialNumber == serial).Id;
            return await worker.ServiceProvider.GetRequiredService<ICertificateRequestService>()
                .MarkAsRevokedAsync(id, "keyCompromise", "operator", Ct);
        }, Ct);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            await Task.WhenAny(revoke, Task.Delay(200, Ct));
            Assert.False(revoke.IsCompleted, "Revocation committed while a full CRL still held an older snapshot.");
        }
        finally
        {
            pause.Release.TrySetResult();
            await full;
            await revoke;
        }

        // Equal timestamps must be included too: clocks can have coarser resolution than consecutive writes.
        var (_, since) = await state.GetBaseAsync(issuer.Issuer, Ct);
        using var check = host.Factory.Services.CreateScope();
        var delta = await check.ServiceProvider.GetRequiredService<ICertificateRequestService>()
            .GetRevokedSinceForCrlAsync(since!.Value, issuer.Scope, Ct);
        Assert.Contains(delta, r => new X509CertificateParser().ReadCertificate(System.Text.Encoding.ASCII.GetBytes(r.CertificatePem!))
            .SerialNumber.Equals(new BigInteger(serial, 16)));
    }

    [Fact]
    public async Task AnOvertakenReservationRetriesBeforeTakingItsSnapshot()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy(algorithm: CertificateKeyAlgorithm.EcdsaP256);
        var issuer = (await host.Registry.GetDefaultAsync(Ct))!;
        using var first = host.Factory.Services.CreateScope();
        var service = first.ServiceProvider.GetRequiredService<ICertificateRequestService>();
        var delayed = DispatchProxy.Create<ICertificateRequestService, PausedServiceCall>();
        var pause = (PausedServiceCall)(object)delayed;
        pause.Target = service;
        pause.MethodName = nameof(ICertificateRequestService.ClaimNextCrlNumberAsync);
        var state = new IssuerCrlState(first.ServiceProvider.GetRequiredService<CertificateRequestDbContext>(), delayed);
        var publisher = new CrlPublisher(service, host.Registry, state, host.Kit.Cache);
        var overtaken = publisher.PublishFullCrlAsync(issuer, Ct);
        await pause.Captured.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
        PublishedCrl newer;
        try
        {
            using var second = host.Factory.Services.CreateScope();
            newer = await second.ServiceProvider.GetRequiredService<CrlPublisher>().PublishFullCrlAsync(issuer, Ct);
        }
        finally
        {
            pause.Release.TrySetResult();
        }
        var retried = await overtaken;
        Assert.True(retried.CrlNumber > newer.CrlNumber);
        Assert.Equal(retried.Bytes, await host.Kit.Cache.GetAsync(CrlCache.Key, Ct));
    }

    [Fact]
    public async Task APartialCacheFailureDoesNotReuseAnAlreadyExposedCrlNumber()
    {
        var cache = new PausedDeltaCache();
        await using var host = new IssuerApiHost(services =>
        {
            services.RemoveAll<IDistributedCache>();
            services.AddSingleton<IDistributedCache>(cache);
        });
        host.Kit.InitializeLegacy(algorithm: CertificateKeyAlgorithm.EcdsaP256);
        var issuer = (await host.Registry.GetDefaultAsync(Ct))!;
        using var scope = host.Factory.Services.CreateScope();
        var publisher = scope.ServiceProvider.GetRequiredService<CrlPublisher>();
        cache.FailDeltaRemoval = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => publisher.PublishFullCrlAsync(issuer, Ct));
        var exposed = new X509CrlParser().ReadCrl(await cache.GetAsync(CrlCache.Key, Ct));
        var exposedNumber = Org.BouncyCastle.Asn1.DerInteger.GetInstance(
            Org.BouncyCastle.X509.Extension.X509ExtensionUtilities.FromExtensionValue(
                exposed.GetExtensionValue(Org.BouncyCastle.Asn1.X509.X509Extensions.CrlNumber))).Value.LongValue;
        cache.FailDeltaRemoval = false;
        var retried = await publisher.PublishFullCrlAsync(issuer, Ct);
        Assert.True(retried.CrlNumber > exposedNumber);
    }

    [Fact]
    public async Task AFullRefreshCannotLeaveADeltaFromItsPreviousBaseCached()
    {
        var cache = new PausedDeltaCache();
        await using var host = new IssuerApiHost(services =>
        {
            services.RemoveAll<IDistributedCache>();
            services.AddSingleton<IDistributedCache>(cache);
        });
        host.Kit.InitializeLegacy(algorithm: CertificateKeyAlgorithm.EcdsaP256);
        await using (var db = host.Kit.Database.CreateContext())
        {
            db.Settings.Single().DeltaCrlEnabled = true;
            await db.SaveChangesAsync(Ct);
        }
        using var client = host.Anonymous();
        using var initial = await client.GetAsync("/crl", Ct);
        Assert.True(initial.IsSuccessStatusCode);
        cache.Pause = true;
        var delta = client.GetAsync("/crl/delta", Ct);
        await cache.Blocked.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var full = Task.Run(async () =>
        {
            using var scope = host.Factory.Services.CreateScope();
            started.SetResult();
            var issuer = (await host.Registry.GetDefaultAsync(Ct))!;
            return await scope.ServiceProvider.GetRequiredService<CrlPublisher>().PublishFullCrlAsync(issuer, Ct);
        }, Ct);
        try
        {
            await started.Task.WaitAsync(TimeSpan.FromSeconds(10), Ct);
            await Task.WhenAny(full, Task.Delay(200, Ct));
            Assert.False(full.IsCompleted, "A full refresh overtook the publication of a delta for the old base.");
        }
        finally
        {
            cache.Release.TrySetResult();
            using var response = await delta;
            Assert.True(response.IsSuccessStatusCode);
            await full;
        }
        Assert.Null(await cache.GetAsync(CrlCache.DeltaKey, Ct));
    }

    public class PausedServiceCall : DispatchProxy
    {
        private bool _paused;
        public ICertificateRequestService Target { get; set; } = null!;
        public string MethodName { get; set; } = nameof(ICertificateRequestService.GetAllRevokedForCrlAsync);
        public TaskCompletionSource Captured { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        protected override object? Invoke(MethodInfo? targetMethod, object?[]? args)
        {
            var result = targetMethod!.Invoke(Target, args);
            if (_paused || targetMethod.Name != MethodName) return result;
            _paused = true;
            return result is Task<long> number ? PauseAsync(number) : PauseAsync((Task<IReadOnlyList<CertificateRequest>>)result!);
        }

        private async Task<T> PauseAsync<T>(Task<T> task)
        {
            var rows = await task;
            Captured.SetResult();
            await Release.Task.WaitAsync(Ct);
            return rows;
        }
    }

    private sealed class PausedDeltaCache : IDistributedCache
    {
        private readonly IDistributedCache _inner = new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions()));
        public bool Pause { get; set; }
        public bool FailDeltaRemoval { get; set; }
        public TaskCompletionSource Blocked { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public byte[]? Get(string key) => _inner.Get(key);
        public Task<byte[]?> GetAsync(string key, CancellationToken token = default) => _inner.GetAsync(key, token);
        public void Set(string key, byte[] value, DistributedCacheEntryOptions options) => _inner.Set(key, value, options);
        public async Task SetAsync(string key, byte[] value, DistributedCacheEntryOptions options, CancellationToken token = default)
        {
            if (Pause && key == CrlCache.DeltaKey)
            {
                Pause = false;
                Blocked.SetResult();
                await Release.Task.WaitAsync(token);
            }
            await _inner.SetAsync(key, value, options, token);
        }
        public void Refresh(string key) => _inner.Refresh(key);
        public Task RefreshAsync(string key, CancellationToken token = default) => _inner.RefreshAsync(key, token);
        public void Remove(string key) => _inner.Remove(key);
        public Task RemoveAsync(string key, CancellationToken token = default) =>
            FailDeltaRemoval && key == CrlCache.DeltaKey
                ? throw new InvalidOperationException("Cache failed after storing the full CRL.")
                : _inner.RemoveAsync(key, token);
    }
}
