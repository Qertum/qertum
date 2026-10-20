using Microsoft.Extensions.Caching.Distributed;
using StackExchange.Redis;

namespace Qertum.Services.Acme;

public interface IAcmeNonceService
{
    string GenerateNonce();
    Task<bool> ConsumeAsync(string nonce, CancellationToken ct = default);
}

public sealed class AcmeNonceService(IDistributedCache cache, IConnectionMultiplexer? redis = null) : IAcmeNonceService
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(10);
    private readonly SemaphoreSlim _memoryConsumeLock = new(1, 1);

    public string GenerateNonce()
    {
        while (true)
        {
            var bytes = new byte[24];
            System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
            var nonce = JwkConverter.Base64UrlEncode(bytes);
            var key = $"acme:nonce:{nonce}";
            if (redis is not null)
            {
                if (!redis.GetDatabase().StringSet(key, "1", Ttl, When.NotExists))
                    continue;
            }
            else
            {
                cache.SetString(key, "1", new DistributedCacheEntryOptions
                {
                    AbsoluteExpirationRelativeToNow = Ttl
                });
            }
            return nonce;
        }
    }

    public async Task<bool> ConsumeAsync(string nonce, CancellationToken ct = default)
    {
        var key = $"acme:nonce:{nonce}";
        if (redis is not null)
            return await redis.GetDatabase().KeyDeleteAsync(key).WaitAsync(ct);

        await _memoryConsumeLock.WaitAsync(ct);
        try
        {
            var value = await cache.GetStringAsync(key, ct);
            if (value is null) return false;
            await cache.RemoveAsync(key, ct);
            return true;
        }
        finally
        {
            _memoryConsumeLock.Release();
        }
    }
}
