using System.Diagnostics.Metrics;

namespace Qertum.Services;

/// <summary>
/// OpenTelemetry instruments for the QueueConsumer's background work: webhook delivery, revocation
/// finalization and background jobs. Tags are low-cardinality outcomes only; never an id, subject or name.
/// </summary>
public sealed class OperationsMetrics : IDisposable
{
    /// <summary>The OTel meter name; must be added to the metrics pipeline in every host that records these.</summary>
    public const string MeterName = "Qertum.Operations";

    private readonly Meter _meter;

    /// <summary>
    /// ca.webhook.deliveries — counter: webhook delivery attempts, tagged <c>outcome</c>:
    /// <c>delivered</c>, <c>retry</c> (failed, will be retried) or <c>failed</c> (permanent).
    /// </summary>
    public Counter<long> WebhookDeliveries { get; }

    /// <summary>
    /// ca.background_job.failures — counter: failed background job attempts, tagged <c>job_type</c>
    /// (a <c>WellKnownJobTypes</c> value) and <c>outcome</c>: <c>retry</c> or <c>failed</c> (attempts exhausted).
    /// </summary>
    public Counter<long> BackgroundJobFailures { get; }

    /// <summary>
    /// ca.certificate.revocations — counter: revocations the QueueConsumer processed, tagged <c>outcome</c>:
    /// <c>revoked</c> (finalized, row is <c>Revoked</c>) or <c>error</c> (finalization threw and will be retried).
    /// </summary>
    public Counter<long> Revocations { get; }

    /// <param name="meterFactory">The host's meter factory.</param>
    /// <param name="crlAgeSecondsProvider">
    /// Backs <c>ca.crl.age</c>; null result reports no measurement. See <see cref="OperationsProbes.OldestCrlAgeSeconds"/>.
    /// </param>
    /// <param name="expiringCertificatesProvider">
    /// Backs <c>ca.certificates.expiring</c>; null result reports no measurement. See <see cref="OperationsProbes.ExpiringCertificates"/>.
    /// </param>
    public OperationsMetrics(
        IMeterFactory meterFactory,
        Func<double?>? crlAgeSecondsProvider = null,
        Func<int?>? expiringCertificatesProvider = null)
    {
        _meter = meterFactory.Create(MeterName);

        WebhookDeliveries = _meter.CreateCounter<long>(
            name: "ca.webhook.deliveries",
            unit: "{attempts}",
            description: "Webhook delivery attempts, tagged by outcome: delivered, retry or failed.");

        Revocations = _meter.CreateCounter<long>(
            name: "ca.certificate.revocations",
            unit: "{certificates}",
            description: "Revocations processed by the queue consumer, tagged by outcome: revoked or error.");

        BackgroundJobFailures = _meter.CreateCounter<long>(
            name: "ca.background_job.failures",
            unit: "{attempts}",
            description: "Failed background job attempts, tagged by job_type and outcome: retry or failed.");

        if (crlAgeSecondsProvider is not null)
            _meter.CreateObservableGauge<double>(
                name: "ca.crl.age",
                observeValues: () => crlAgeSecondsProvider() is { } age ? [new Measurement<double>(age)] : [],
                unit: "s",
                description: "Seconds since the oldest base CRL was published. Absent before any CRL exists or when it cannot be read.");

        if (expiringCertificatesProvider is not null)
            _meter.CreateObservableGauge<int>(
                name: "ca.certificates.expiring",
                observeValues: () => expiringCertificatesProvider() is { } count ? [new Measurement<int>(count)] : [],
                unit: "{certificates}",
                description: "Issued certificates that expire within the ExpiringSoonDays window. Absent when it cannot be read.");
    }

    public void Dispose() => _meter.Dispose();
}
