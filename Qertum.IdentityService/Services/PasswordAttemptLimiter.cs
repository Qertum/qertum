using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using StackExchange.Redis;

namespace Qertum.IdentityService.Services;

public enum PasswordAttemptPurpose
{
    /// <summary>Sign-in, keyed by username and client address: one address cannot lock the account for another.</summary>
    Login,
    StepUp,
    ChangePassword,

    /// <summary>Sign-in, keyed by username alone, with the looser <see cref="PasswordAttemptLimiter.AccountCeiling"/>: slows a guess spread across addresses.</summary>
    LoginAccount,

    /// <summary>
    /// Sign-in, keyed by client address alone, with <see cref="PasswordAttemptLimiter.AddressCeiling"/>: a new username on
    /// every attempt meets neither other limit, and each attempt costs a password hash. A successful sign-in is
    /// refunded, so many people signing in behind one address do not use it up.
    /// </summary>
    LoginAddress
}

public interface IPasswordAttemptLimiter
{
    /// <summary>Reserves an attempt and returns its number, or zero when the limit is reached.</summary>
    Task<int> ReserveAsync(PasswordAttemptPurpose purpose, string identity, CancellationToken cancellationToken);

    /// <summary>Clears attempts after a successful password check.</summary>
    Task ClearAsync(PasswordAttemptPurpose purpose, string identity, CancellationToken cancellationToken);

    /// <summary>Gives back one reserved attempt (never below zero), for a bucket that counts only failures but is shared by many identities.</summary>
    Task RefundAsync(PasswordAttemptPurpose purpose, string identity, CancellationToken cancellationToken);
}

public sealed class PasswordAttemptLimiter(
    IMemoryCache memoryCache,
    TimeProvider timeProvider,
    IConnectionMultiplexer? redis = null) : IPasswordAttemptLimiter
{
    public const int MaxAttempts = 5;

    /// <summary>Failed sign-ins per username across every client address in <see cref="LoginWindow"/>.</summary>
    public const int AccountCeiling = 50;

    /// <summary>Failed sign-ins per client address across every username in <see cref="LoginWindow"/>.</summary>
    public const int AddressCeiling = 100;
    public static readonly TimeSpan LoginWindow = TimeSpan.FromMinutes(15);
    public static readonly TimeSpan AccountWindow = TimeSpan.FromSeconds(60);

    private const string ReserveScript = """
        local count = tonumber(redis.call('GET', KEYS[1]) or '0')
        if count >= tonumber(ARGV[1]) then return 0 end
        count = redis.call('INCR', KEYS[1])
        if count == 1 or ARGV[3] == '1' then
            redis.call('PEXPIRE', KEYS[1], ARGV[2])
        end
        return count
        """;

    private const string RefundScript = """
        local count = tonumber(redis.call('GET', KEYS[1]) or '0')
        if count > 0 then return redis.call('DECR', KEYS[1]) end
        return 0
        """;

    private readonly object _memoryGate = new();

    public async Task<int> ReserveAsync(
        PasswordAttemptPurpose purpose, string identity, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
        var key = Key(purpose, identity);
        var window = Window(purpose);
        var limit = Limit(purpose);
        var sliding = purpose is PasswordAttemptPurpose.StepUp or PasswordAttemptPurpose.ChangePassword;

        if (redis is not null)
        {
            var result = await redis.GetDatabase().ScriptEvaluateAsync(
                ReserveScript, [key], [limit, (long)window.TotalMilliseconds, sliding ? 1 : 0])
                .WaitAsync(cancellationToken);
            return (int)(long)result;
        }

        cancellationToken.ThrowIfCancellationRequested();
        lock (_memoryGate)
        {
            var now = timeProvider.GetUtcNow();
            var entry = memoryCache.TryGetValue(key, out AttemptState? tracked) && tracked!.ExpiresAt > now
                ? tracked : null;
            if (entry?.Count >= limit) return 0;

            var count = (entry?.Count ?? 0) + 1;
            var expiresAt = entry is null || sliding ? now + window : entry.ExpiresAt;
            memoryCache.Set(key, new AttemptState(count, expiresAt),
                new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = window * 2 });
            return count;
        }
    }

    public async Task ClearAsync(
        PasswordAttemptPurpose purpose, string identity, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
        var key = Key(purpose, identity);
        if (redis is not null)
        {
            await redis.GetDatabase().KeyDeleteAsync(key).WaitAsync(cancellationToken);
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();
        lock (_memoryGate) memoryCache.Remove(key);
    }

    public async Task RefundAsync(
        PasswordAttemptPurpose purpose, string identity, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identity);
        var key = Key(purpose, identity);
        if (redis is not null)
        {
            await redis.GetDatabase().ScriptEvaluateAsync(RefundScript, [key]).WaitAsync(cancellationToken);
            return;
        }

        cancellationToken.ThrowIfCancellationRequested();
        lock (_memoryGate)
        {
            if (memoryCache.TryGetValue(key, out AttemptState? tracked) && tracked!.Count > 0 && tracked.ExpiresAt > timeProvider.GetUtcNow())
                memoryCache.Set(key, tracked with { Count = tracked.Count - 1 },
                    new MemoryCacheEntryOptions { AbsoluteExpiration = tracked.ExpiresAt + Window(purpose) });
        }
    }

    private static int Limit(PasswordAttemptPurpose purpose) => purpose switch
    {
        PasswordAttemptPurpose.LoginAccount => AccountCeiling,
        PasswordAttemptPurpose.LoginAddress => AddressCeiling,
        _ => MaxAttempts
    };

    private static TimeSpan Window(PasswordAttemptPurpose purpose) => purpose switch
    {
        PasswordAttemptPurpose.Login or PasswordAttemptPurpose.LoginAccount or PasswordAttemptPurpose.LoginAddress => LoginWindow,
        PasswordAttemptPurpose.StepUp or PasswordAttemptPurpose.ChangePassword => AccountWindow,
        _ => throw new ArgumentOutOfRangeException(nameof(purpose))
    };

    private static string Key(PasswordAttemptPurpose purpose, string identity)
    {
        var bytes = Encoding.UTF8.GetBytes(identity.ToLowerInvariant());
        var hash = Convert.ToHexString(SHA256.HashData(bytes));
        return $"identity:password-attempts:v1:{purpose}:{hash}";
    }

    private sealed record AttemptState(int Count, DateTimeOffset ExpiresAt);
}
