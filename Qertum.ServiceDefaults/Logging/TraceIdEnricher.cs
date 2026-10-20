using Serilog.Core;
using Serilog.Events;

namespace Qertum.ServiceDefaults.Logging;

/// <summary>
/// Adds <c>RequestTrace</c> to every log event: the trace id of the request that wrote it, in the bare
/// 32-hex form the API returns as <c>X-Correlation-Id</c>, so an operator can grep the console for an id
/// they were given. Serilog already captures the trace id of the current activity on each event
/// (<see cref="LogEvent.TraceId"/>, rendered by the built-in <c>{TraceId}</c> token, which is empty
/// outside a request); this only turns "none" into <c>-</c> so the column stays present and greppable.
/// </summary>
public sealed class TraceIdEnricher : ILogEventEnricher
{
    /// <summary>The property the console template prints.</summary>
    public const string PropertyName = "RequestTrace";

    /// <inheritdoc />
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory) =>
        logEvent.AddPropertyIfAbsent(propertyFactory.CreateProperty(PropertyName, logEvent.TraceId?.ToString() ?? "-"));
}

/// <summary>The console line every host writes.</summary>
public static class ConsoleLog
{
    /// <summary>Serilog's default console template with the trace id after the level: <c>[10:41:03 ERR 4bf9…] message</c>.</summary>
    public const string OutputTemplate = "[{Timestamp:HH:mm:ss} {Level:u3} {RequestTrace:l}] {Message:lj}{NewLine}{Exception}";
}
