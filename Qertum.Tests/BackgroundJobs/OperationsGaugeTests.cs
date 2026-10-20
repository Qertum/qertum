using System.Diagnostics.Metrics;
using Qertum.Services;

namespace Qertum.Tests.BackgroundJobs;

/// <summary>
/// The two gauges an operator alerts on for slow decay rather than events: how stale the published
/// CRL base is, and how many issued certificates are about to expire.
/// </summary>
public sealed class OperationsGaugeTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static OperationsMetrics NewMetrics(BackgroundJobTestHost host, IMeterFactory meters)
    {
        var scopes = host.Services.GetRequiredService<IServiceScopeFactory>();
        return new OperationsMetrics(meters,
            OperationsProbes.OldestCrlAgeSeconds(scopes, host.Clock),
            OperationsProbes.ExpiringCertificates(scopes, host.Clock));
    }

    private static async Task SeedSettingsAsync(BackgroundJobTestHost host, DateTime? baseThisUpdateUtc, int expiringSoonDays = 30)
    {
        await using var db = host.Database.CreateContext();
        db.Settings.Add(new CaSettings
        {
            Id = 1, PqcStage = PqcStage.Off, ExpiringSoonDays = expiringSoonDays,
            BaseCrlNumber = baseThisUpdateUtc is null ? null : 1, BaseCrlThisUpdateUtc = baseThisUpdateUtc
        });
        await db.SaveChangesAsync(Ct);
    }

    private static async Task SeedCertificateAsync(BackgroundJobTestHost host, CertificateRequestStatus status, DateTime? validTo)
    {
        await using var db = host.Database.CreateContext();
        db.CertificateRequests.Add(new CertificateRequest
        {
            CommonName = $"{Guid.NewGuid():N}.contoso.local", RequestedBy = "test", Status = status, ValidTo = validTo
        });
        await db.SaveChangesAsync(Ct);
    }

    [Fact]
    public async Task CrlAge_ReportsSecondsSinceTheBaseCrlWasPublished()
    {
        await using var host = BackgroundJobTestHost.Create();
        await SeedSettingsAsync(host, host.Clock.GetUtcNow().UtcDateTime.AddHours(-3));
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = NewMetrics(host, meters);

        recorder.Observe();

        Assert.Equal(3 * 3600, recorder.Latest("ca.crl.age"));
    }

    [Fact]
    public async Task CrlAge_ReportsNothingBeforeAnyCrlWasPublished()
    {
        await using var host = BackgroundJobTestHost.Create();
        await SeedSettingsAsync(host, baseThisUpdateUtc: null);
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = NewMetrics(host, meters);

        recorder.Observe();

        // Zero would read as "fresh"; no measurement lets an alert rule treat it as absent data.
        Assert.Null(recorder.Latest("ca.crl.age"));
    }

    [Fact]
    public async Task CrlAge_ReportsNothingWithoutACa()
    {
        await using var host = BackgroundJobTestHost.Create(initializeCa: false);
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = NewMetrics(host, meters);

        recorder.Observe();

        Assert.Null(recorder.Latest("ca.crl.age"));
    }

    [Fact]
    public async Task ExpiringCertificates_CountsIssuedCertificatesInsideTheExpiringSoonWindow()
    {
        await using var host = BackgroundJobTestHost.Create();
        await SeedSettingsAsync(host, host.Clock.GetUtcNow().UtcDateTime, expiringSoonDays: 30);
        var now = host.Clock.GetUtcNow().UtcDateTime;
        await SeedCertificateAsync(host, CertificateRequestStatus.Issued, now.AddDays(10));  // counts
        await SeedCertificateAsync(host, CertificateRequestStatus.Issued, now.AddDays(29));  // counts
        await SeedCertificateAsync(host, CertificateRequestStatus.Issued, now.AddDays(60));  // too far out
        await SeedCertificateAsync(host, CertificateRequestStatus.Issued, now.AddDays(-1));  // already expired
        await SeedCertificateAsync(host, CertificateRequestStatus.Revoked, now.AddDays(10)); // not live
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = NewMetrics(host, meters);

        recorder.Observe();

        Assert.Equal(2, recorder.Latest("ca.certificates.expiring"));
    }

    [Fact]
    public async Task ExpiringCertificates_ReportsZeroWhenNothingIsExpiring()
    {
        await using var host = BackgroundJobTestHost.Create();
        await SeedSettingsAsync(host, host.Clock.GetUtcNow().UtcDateTime);
        var meters = MetricsRecorder.CreateMeterFactory();
        using var recorder = new MetricsRecorder(meters, OperationsMetrics.MeterName);
        using var metrics = NewMetrics(host, meters);

        recorder.Observe();

        Assert.Equal(0, recorder.Latest("ca.certificates.expiring"));
    }
}
