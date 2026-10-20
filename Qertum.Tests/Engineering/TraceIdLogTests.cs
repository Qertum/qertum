using System.Diagnostics;
using System.Text.RegularExpressions;
using Qertum.ServiceDefaults.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Display;

namespace Qertum.Tests.Engineering;

/// <summary>
/// An operator who quotes a correlation id from an API response must be able to grep the console log
/// for it, so every console line carries the trace id of the request that wrote it.
/// </summary>
public sealed class TraceIdLogTests
{
    private static string Render(Action<Serilog.ILogger> write)
    {
        var sink = new StringSink(new MessageTemplateTextFormatter(ConsoleLog.OutputTemplate));
        using var logger = new LoggerConfiguration().Enrich.With<TraceIdEnricher>().WriteTo.Sink(sink).CreateLogger();
        write(logger);
        return sink.Text;
    }

    private static Activity StartActivity(out IDisposable cleanup)
    {
        var source = new ActivitySource("Qertum.Tests.TraceIdLog");
        var listener = new ActivityListener
        {
            ShouldListenTo = s => s.Name == source.Name,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
        };
        ActivitySource.AddActivityListener(listener);
        var activity = source.StartActivity("request")!;
        cleanup = new Disposables(activity, listener, source);
        return activity;
    }

    [Fact]
    public void ALineWrittenInsideARequest_PrintsItsTraceId()
    {
        var activity = StartActivity(out var cleanup);
        using (cleanup)
        {
            var text = Render(l => l.Error("boom"));

            Assert.Contains($" ERR {activity.TraceId}] boom", text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheTraceIdIsTheBareThirtyTwoHexForm_NotTheLongTraceparentForm()
    {
        var activity = StartActivity(out var cleanup);
        using (cleanup)
        {
            var text = Render(l => l.Information("hello"));

            Assert.Matches(new Regex(@"^\[\d\d:\d\d:\d\d INF [0-9a-f]{32}\] hello"), text);
            Assert.DoesNotContain("00-", text, StringComparison.Ordinal);
            Assert.Equal(32, activity.TraceId.ToString().Length);
        }
    }

    [Fact]
    public void ALineWrittenOutsideARequest_PrintsADash_SoTheColumnIsStillGreppable()
    {
        Assert.Null(Activity.Current);

        var text = Render(l => l.Warning("startup"));

        Assert.Matches(new Regex(@"^\[\d\d:\d\d:\d\d WRN -\] startup"), text);
    }

    private sealed class StringSink(MessageTemplateTextFormatter formatter) : ILogEventSink
    {
        private readonly StringWriter _writer = new();

        public string Text => _writer.ToString();

        public void Emit(LogEvent logEvent) => formatter.Format(logEvent, _writer);
    }

    private sealed class Disposables(params IDisposable[] items) : IDisposable
    {
        public void Dispose()
        {
            foreach (var item in items) item.Dispose();
        }
    }
}
