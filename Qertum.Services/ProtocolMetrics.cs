using System.Diagnostics.Metrics;

namespace Qertum.Services;

/// <summary>
/// OpenTelemetry instruments for the enrollment protocols (ACME, EST). Tags are low-cardinality
/// outcomes only; never a domain, account, credential or id.
/// </summary>
public sealed class ProtocolMetrics : IDisposable
{
    /// <summary>The OTel meter name; must be added to the metrics pipeline in every host that records these.</summary>
    public const string MeterName = "Qertum.Protocols";

    private readonly Meter _meter;

    /// <summary>
    /// ca.acme.orders — counter: ACME order transitions, tagged <c>outcome</c>:
    /// <c>created</c>, <c>valid</c> (certificate issued) or <c>invalid</c> (challenge exhausted or request rejected).
    /// </summary>
    public Counter<long> AcmeOrders { get; }

    /// <summary>
    /// ca.acme.challenges — counter: ACME challenge validation attempts, tagged <c>type</c> (http-01, dns-01),
    /// <c>outcome</c> (<c>valid</c>, <c>retry</c>, <c>failed</c> once attempts are exhausted) and <c>failure</c>
    /// (an <c>AcmeChallengeFailure</c> name, <c>None</c> when valid).
    /// </summary>
    public Counter<long> AcmeChallenges { get; }

    /// <summary>
    /// ca.est.enrollments — counter: EST enrollment requests, tagged <c>operation</c> (<c>enroll</c>, <c>reenroll</c>)
    /// and <c>outcome</c>: <c>issued</c> (200), <c>pending</c> (202), <c>unauthorized</c> (401/403),
    /// <c>refused</c> (other 4xx) or <c>error</c> (5xx).
    /// </summary>
    public Counter<long> EstEnrollments { get; }

    public ProtocolMetrics(IMeterFactory meterFactory)
    {
        _meter = meterFactory.Create(MeterName);

        AcmeOrders = _meter.CreateCounter<long>(
            name: "ca.acme.orders",
            unit: "{orders}",
            description: "ACME order transitions, tagged by outcome: created, valid or invalid.");

        AcmeChallenges = _meter.CreateCounter<long>(
            name: "ca.acme.challenges",
            unit: "{attempts}",
            description: "ACME challenge validation attempts, tagged by type, outcome (valid, retry, failed) and failure category.");

        EstEnrollments = _meter.CreateCounter<long>(
            name: "ca.est.enrollments",
            unit: "{requests}",
            description: "EST enrollment requests, tagged by operation and outcome.");
    }

    public void Dispose() => _meter.Dispose();
}
