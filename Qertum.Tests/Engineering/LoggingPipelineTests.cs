using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Qertum.Tests.Engineering;

/// <summary>
/// Every host logs through Serilog, set up once in AddServiceDefaults, behind the unchanged
/// ILogger&lt;T&gt;. Serilog forwards each event to the registered logger providers, which is how the
/// OpenTelemetry provider keeps exporting to the Aspire dashboard with its trace context.
/// </summary>
public sealed class LoggingPipelineTests
{
    [Fact]
    public void SerilogIsTheLoggingImplementation()
    {
        using var host = BuildHost(new CapturingProvider());

        var factory = host.Services.GetRequiredService<ILoggerFactory>();

        Assert.Contains("Serilog", factory.GetType().FullName, StringComparison.Ordinal);
    }

    [Fact]
    public void EventsReachTheRegisteredProviders_IncludingTheOpenTelemetryExporter()
    {
        var capture = new CapturingProvider();
        using var host = BuildHost(capture);

        host.Services.GetRequiredService<ILogger<LoggingPipelineTests>>().LogWarning("forwarded {Value}", 42);

        Assert.Contains(capture.Entries, e => e.Message == "forwarded 42" && e.Level == LogLevel.Warning);
        Assert.Contains(host.Services.GetServices<ILoggerProvider>(),
            p => p.GetType().FullName!.Contains("OpenTelemetry", StringComparison.Ordinal));
    }

    [Fact]
    public void EachHostKeepsItsOwnLogger_EvenAfterAnotherHostIsBuilt()
    {
        // Serilog's default replaces the static Log.Logger and routes every host's ILoggerFactory
        // through it, so the most recently built host received every other host's events. Test hosts
        // run side by side, and an event that lands in the wrong host's providers is simply lost.
        var first = new CapturingProvider();
        using var firstHost = BuildHost(first);
        var second = new CapturingProvider();
        using var secondHost = BuildHost(second);

        firstHost.Services.GetRequiredService<ILogger<LoggingPipelineTests>>().LogWarning("belongs to the first host");

        Assert.Contains(first.Entries, e => e.Message == "belongs to the first host");
        Assert.DoesNotContain(second.Entries, e => e.Message == "belongs to the first host");
    }

    [Fact]
    public void LevelsComeFromTheSerilogSection()
    {
        var capture = new CapturingProvider();
        using var host = BuildHost(capture, new Dictionary<string, string?>
        {
            ["Serilog:MinimumLevel:Default"] = "Information",
            ["Serilog:MinimumLevel:Override:Noisy"] = "Error",
        });
        var factory = host.Services.GetRequiredService<ILoggerFactory>();

        factory.CreateLogger("Quiet").LogDebug("debug is below the default");
        factory.CreateLogger("Noisy.Component").LogWarning("warning is below the override");
        factory.CreateLogger("Quiet").LogInformation("information passes");

        Assert.Equal(["information passes"], capture.Entries.Select(e => e.Message));
    }

    [Fact]
    public void AnEventCarriesTheActivityItWasWrittenIn()
    {
        // The OpenTelemetry provider reads Activity.Current when it receives an event. Serilog forwards
        // synchronously, so the activity is still current and the dashboard can link log to trace.
        var capture = new CapturingProvider();
        using var host = BuildHost(capture);
        using var source = new ActivitySource("Qertum.Tests.Logging");
        using var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);

        using (var activity = source.StartActivity("request"))
        {
            host.Services.GetRequiredService<ILogger<LoggingPipelineTests>>().LogInformation("inside");
            Assert.Equal(activity!.TraceId, Assert.Single(capture.Entries).TraceId);
        }
    }

    [Fact]
    public void NoHostConfiguresLevelsThroughTheIgnoredLoggingSection()
    {
        // Serilog owns filtering, so a "Logging:LogLevel" section would look like configuration and do
        // nothing. The AppHost is Aspire's orchestrator, not a service, and keeps Microsoft logging.
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(root.FullName, "Qertum.sln"))) root = root.Parent!;

        var offenders = Directory.EnumerateDirectories(root.FullName, "Qertum.*")
            .Where(d => !d.EndsWith("Qertum.AppHost", StringComparison.Ordinal) && !d.EndsWith("Qertum.Tests", StringComparison.Ordinal))
            .SelectMany(d => Directory.EnumerateFiles(d, "appsettings*.json"))
            .Where(f => System.Text.Json.JsonDocument.Parse(File.ReadAllText(f)).RootElement.TryGetProperty("Logging", out _))
            .Select(f => Path.GetRelativePath(root.FullName, f))
            .ToList();

        Assert.True(offenders.Count == 0, "Use Serilog:MinimumLevel instead of Logging:LogLevel in: " + string.Join(", ", offenders));
    }

    private static IHost BuildHost(CapturingProvider capture, Dictionary<string, string?>? settings = null)
    {
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Test" });
        builder.Configuration.AddInMemoryCollection(settings ?? []);
        builder.AddServiceDefaults();
        builder.Services.AddSingleton<ILoggerProvider>(capture);
        return builder.Build();
    }

    private sealed class CapturingProvider : ILoggerProvider
    {
        public ConcurrentQueue<(LogLevel Level, string Message, ActivityTraceId TraceId)> Entries { get; } = new();

        public ILogger CreateLogger(string categoryName) => new Logger(Entries);

        public void Dispose() { }

        private sealed class Logger(ConcurrentQueue<(LogLevel, string, ActivityTraceId)> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                entries.Enqueue((logLevel, formatter(state, exception), Activity.Current?.TraceId ?? default));
        }
    }
}
