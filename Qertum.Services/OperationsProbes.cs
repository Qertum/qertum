using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services.Issuers;

namespace Qertum.Services;

/// <summary>
/// Read-only measurements behind <see cref="OperationsMetrics"/> gauges. Each returns null when it cannot
/// measure (no CA yet, database unreachable), because a gauge that reported 0 would read as healthy.
/// </summary>
public static class OperationsProbes
{
    /// <summary>
    /// Seconds since the oldest published base CRL among the issuers that sign their own CRL. An issuer
    /// that has not published one yet is skipped, not counted as fresh or as old.
    /// </summary>
    public static Func<double?> OldestCrlAgeSeconds(IServiceScopeFactory scopes, TimeProvider clock) => () =>
    {
        try
        {
            using var scope = scopes.CreateScope();
            var registry = scope.ServiceProvider.GetRequiredService<IIssuerRegistry>();
            var crlState = scope.ServiceProvider.GetRequiredService<IssuerCrlState>();
            var now = clock.GetUtcNow().UtcDateTime;

            double? oldest = null;
            foreach (var handle in registry.GetCrlSigningHandlesAsync().GetAwaiter().GetResult())
            {
                var (_, thisUpdate) = crlState.GetBaseAsync(handle.Issuer, CancellationToken.None).GetAwaiter().GetResult();
                if (thisUpdate is null) continue;
                var age = Math.Max(0, (now - thisUpdate.Value).TotalSeconds);
                oldest = oldest is null ? age : Math.Max(oldest.Value, age);
            }
            return oldest;
        }
        catch
        {
            return null;
        }
    };

    /// <summary>
    /// Issued certificates that expire within <c>CaSettings.ExpiringSoonDays</c> (30 before settings exist),
    /// the same window the dashboard uses. Already expired certificates are not counted.
    /// </summary>
    public static Func<int?> ExpiringCertificates(IServiceScopeFactory scopes, TimeProvider clock) => () =>
    {
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var now = clock.GetUtcNow().UtcDateTime;
            // AsNoTracking and no GetSettingsAsync: a read-only probe must not create the settings row.
            var days = db.Settings.AsNoTracking().Select(s => (int?)s.ExpiringSoonDays).FirstOrDefault() ?? 30;
            var horizon = now.AddDays(days);
            return db.CertificateRequests.Count(r =>
                r.Status == CertificateRequestStatus.Issued && r.ValidTo != null && r.ValidTo > now && r.ValidTo <= horizon);
        }
        catch
        {
            return null;
        }
    };
}
