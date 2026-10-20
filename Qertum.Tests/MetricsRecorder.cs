using System.Diagnostics.Metrics;
using Microsoft.Extensions.DependencyInjection;

namespace Qertum.Tests;

/// <summary>
/// Collects what a <see cref="Meter"/> publishes so a test can assert on instrument names and tags,
/// the contract an operator's alert rules depend on.
/// </summary>
internal sealed class MetricsRecorder : IDisposable
{
    private readonly MeterListener _listener = new();
    private readonly List<Measurement> _measurements = [];
    private readonly object _gate = new();

    /// <summary>
    /// Listens to meters named <paramref name="meterNames"/> that were created by <paramref name="meters"/> only.
    /// Listeners match by name process-wide, so without the scope a parallel test's host would leak
    /// into the sums asserted here.
    /// </summary>
    public MetricsRecorder(IMeterFactory meters, params string[] meterNames)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (ReferenceEquals(instrument.Meter.Scope, meters) && meterNames.Contains(instrument.Meter.Name))
                listener.EnableMeasurementEvents(instrument);
        };
        _listener.SetMeasurementEventCallback<long>((i, v, tags, _) => Record(i, v, tags));
        _listener.SetMeasurementEventCallback<int>((i, v, tags, _) => Record(i, v, tags));
        _listener.SetMeasurementEventCallback<double>((i, v, tags, _) => Record(i, v, tags));
        _listener.Start();
    }

    /// <summary>A real <see cref="IMeterFactory"/>, as the hosts get from <c>AddMetrics()</c>.</summary>
    public static IMeterFactory CreateMeterFactory() =>
        new ServiceCollection().AddMetrics().BuildServiceProvider().GetRequiredService<IMeterFactory>();

    /// <summary>One published value with the tags it carried.</summary>
    public sealed record Measurement(string Instrument, double Value, IReadOnlyDictionary<string, object?> Tags);

    /// <summary>Asks every observable instrument to report now.</summary>
    public void Observe() => _listener.RecordObservableInstruments();

    /// <summary>Sum of counter measurements for <paramref name="instrument"/> whose tags include every given pair.</summary>
    public double Sum(string instrument, params (string Key, string Value)[] tags)
    {
        lock (_gate)
            return _measurements
                .Where(m => m.Instrument == instrument && tags.All(t => m.Tags.TryGetValue(t.Key, out var v) && Equals(v, t.Value)))
                .Sum(m => m.Value);
    }

    /// <summary>The newest value of an observable gauge, or null when it reported nothing.</summary>
    public double? Latest(string instrument)
    {
        lock (_gate)
            return _measurements.LastOrDefault(m => m.Instrument == instrument)?.Value;
    }

    /// <summary>Every tag set seen for <paramref name="instrument"/>, so a test can pin the tag keys.</summary>
    public IReadOnlyList<IReadOnlyDictionary<string, object?>> TagSets(string instrument)
    {
        lock (_gate)
            return _measurements.Where(m => m.Instrument == instrument).Select(m => m.Tags).ToList();
    }

    private void Record<T>(Instrument instrument, T value, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        where T : struct
    {
        var copy = new Dictionary<string, object?>();
        foreach (var tag in tags) copy[tag.Key] = tag.Value;
        lock (_gate)
            _measurements.Add(new Measurement(instrument.Name, Convert.ToDouble(value), copy));
    }

    public void Dispose() => _listener.Dispose();
}
