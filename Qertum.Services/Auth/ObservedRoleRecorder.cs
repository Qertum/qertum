using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Qertum.Services.Auth;

/// <summary>Records role names seen in bearer tokens. Never fails the caller.</summary>
public interface IObservedRoleRecorder
{
    /// <summary>Upserts each valid role's sighting, throttled per role; swallows every failure.</summary>
    Task RecordAsync(IReadOnlyCollection<string> roles, CancellationToken cancellationToken = default);
}

/// <summary>
/// Upserts <see cref="ObservedRole"/> rows at most once per <see cref="Throttle"/> per role per
/// instance. Stores the role name and timestamps only — never who carried the role.
/// </summary>
public sealed class ObservedRoleRecorder(
    CertificateRequestDbContext dbContext,
    IMemoryCache cache,
    TimeProvider timeProvider,
    ILogger<ObservedRoleRecorder> logger) : IObservedRoleRecorder
{
    /// <summary>Roles beyond this many in one token are not recorded.</summary>
    public const int MaxRolesPerRequest = 50;

    /// <summary>Minimum interval between writes for one role on one instance.</summary>
    public static readonly TimeSpan Throttle = TimeSpan.FromHours(1);

    /// <inheritdoc />
    public async Task RecordAsync(IReadOnlyCollection<string> roles, CancellationToken cancellationToken = default)
    {
        try
        {
            foreach (var role in roles.Where(RoleNameRules.IsValid).Take(MaxRolesPerRequest))
            {
                var key = "observed-role:" + role.ToLowerInvariant();
                var now = timeProvider.GetUtcNow();

                // The cached value is the last write time, compared on the injected clock; the entry's
                // own expiry only bounds memory.
                if (cache.TryGetValue(key, out DateTimeOffset lastWrite) && now - lastWrite < Throttle)
                    continue;

                var nowUtc = now.UtcDateTime;
                await dbContext.Database.ExecuteSqlAsync(
                    $"INSERT INTO ObservedRoles (Role, FirstSeenUtc, LastSeenUtc) VALUES ({role}, {nowUtc}, {nowUtc}) ON CONFLICT(Role) DO UPDATE SET LastSeenUtc = excluded.LastSeenUtc",
                    cancellationToken);

                // Set only after a successful write, so a failed write retries on the next request.
                cache.Set(key, now, new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = Throttle * 2 });
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Recording observed roles failed; the request continues.");
        }
    }
}
