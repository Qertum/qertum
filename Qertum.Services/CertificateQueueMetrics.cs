using System.Diagnostics.Metrics;

namespace Qertum.Services;

/// <summary>
/// OpenTelemetry instruments for the certificate request queue consumer.
/// Register as a singleton and inject wherever metrics need to be recorded.
/// </summary>
public sealed class CertificateQueueMetrics : IDisposable
{
    /// <summary>The OTel meter name — must be added to the metrics pipeline in every host that uses this class.</summary>
    public const string MeterName = "Qertum.Queue";

    private readonly Meter _meter;

    /// <summary>
    /// ca.certificate.issue_duration — histogram: wall-clock time from dequeue to MarkAsIssued, in seconds.
    /// </summary>
    public Histogram<double> IssueDuration { get; }

    /// <summary>
    /// ca.certificate.issue_errors — counter: number of unhandled exceptions during certificate processing.
    /// Tagged with <c>algorithm</c> and <c>certificate.type</c>.
    /// </summary>
    public Counter<long> IssueErrors { get; }

    /// <summary>
    /// ca.certificate.issued_total — counter: number of successfully issued certificates.
    /// Tagged with <c>algorithm</c> and <c>certificate.type</c> to allow per-algorithm and per-type breakdowns.
    /// </summary>
    public Counter<long> IssuedTotal { get; }

    public CertificateQueueMetrics(
        IMeterFactory meterFactory,
        Func<int> queueDepthProvider,
        Func<int> activeCertsProvider,
        Func<int> expiredCertsProvider,
        Func<int> revokedCertsProvider)
    {
        _meter = meterFactory.Create(MeterName);

        // Observable gauges report via the callbacks below; the Meter keeps them registered for
        // the lifetime of this instance, so they don't need to be exposed as fields or properties.
        _meter.CreateObservableGauge(
            name: "ca.queue.depth",
            observeValue: queueDepthProvider,
            unit: "{requests}",
            description: "Number of Approved certificate requests waiting to be issued.");

        IssueDuration = _meter.CreateHistogram(
            name: "ca.certificate.issue_duration",
            unit: "s",
            description: "Wall-clock seconds from dequeue to certificate issuance.",
            advice: new InstrumentAdvice<double>
            {
                HistogramBucketBoundaries = [0.1, 0.25, 0.5, 1, 2.5, 5, 10]
            });

        IssueErrors = _meter.CreateCounter<long>(
            name: "ca.certificate.issue_errors",
            unit: "{errors}",
            description: "Number of unhandled errors during certificate request processing.");

        IssuedTotal = _meter.CreateCounter<long>(
            name: "ca.certificate.issued_total",
            unit: "{certificates}",
            description: "Total number of successfully issued certificates, tagged by algorithm and type.");

        _meter.CreateObservableGauge(
            name: "ca.certificates.active",
            observeValue: activeCertsProvider,
            unit: "{certificates}",
            description: "Number of issued certificates whose validity period has not yet expired.");

        _meter.CreateObservableGauge(
            name: "ca.certificates.expired",
            observeValue: expiredCertsProvider,
            unit: "{certificates}",
            description: "Number of issued certificates whose validity period has passed.");

        _meter.CreateObservableGauge(
            name: "ca.certificates.revoked",
            observeValue: revokedCertsProvider,
            unit: "{certificates}",
            description: "Number of certificates in the Revoked state.");
    }

    public void Dispose() => _meter.Dispose();
}
