using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Qertum.ServiceDefaults.Logging;
using Serilog;
using Serilog.Core;
using Serilog.Events;
using Serilog.Formatting.Display;

namespace Qertum.Tests.Engineering;

/// <summary>
/// The console template prints string values raw (<c>{Message:lj}</c>), and values such as a request's common name,
/// an issuer or policy name, a webhook URL or a delivery error are typed by people or come from other systems. A line
/// break in one of them would start a new console line that looks like Qertum wrote it (CodeQL cs/log-forging), so
/// every string value has its control characters escaped before any sink sees it.
/// </summary>
public sealed class LogForgingTests
{
    private static readonly string Lf = "\n", Cr = "\r";

    private static string Render(Action<Serilog.ILogger> write)
    {
        var sink = new StringSink(new MessageTemplateTextFormatter(ConsoleLog.OutputTemplate));
        using var logger = new LoggerConfiguration()
            .Enrich.With<TraceIdEnricher>()
            .Enrich.With<ControlCharacterEscapingEnricher>()
            .WriteTo.Sink(sink).CreateLogger();
        write(logger);
        return sink.Text;
    }

    [Fact]
    public void ALineBreakInAValue_CannotStartAForgedConsoleLine()
    {
        var text = Render(l => l.Information("Request {CommonName} created", "x" + Lf + "[12:00:00 ERR -] forged"));

        Assert.Single(text.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains(@"Request x\n[12:00:00 ERR -] forged created", text, StringComparison.Ordinal);
    }

    // Character codes, not literals: the compiler reads U+0085, U+2028 and U+2029 as line breaks even when escaped.
    [Theory]
    [InlineData(0x0D, @"\r")]
    [InlineData(0x09, @"\t")]
    [InlineData(0x1B, @"\u001B")]
    [InlineData(0x85, @"\u0085")]
    [InlineData(0x2028, @"\u2028")]
    [InlineData(0x2029, @"\u2029")]
    public void EveryControlCharacterAndUnicodeLineSeparator_IsEscaped(int code, string escaped)
    {
        var c = (char)code;
        var text = Render(l => l.Information("name {Name}", "a" + c + "b"));

        Assert.Contains("name a" + escaped + "b", text, StringComparison.Ordinal);
        Assert.DoesNotContain(c.ToString(), text.TrimEnd(), StringComparison.Ordinal);
    }

    [Fact]
    public void AnOrdinaryValue_PrintsExactlyAsBefore()
    {
        var text = Render(l => l.Information("Signed {CommonName} for {Count} days", "api.example.com", 90));

        Assert.EndsWith("] Signed api.example.com for 90 days" + Environment.NewLine, text, StringComparison.Ordinal);
    }

    [Fact]
    public void AContextPropertyIsEscapedToo()
    {
        var text = Render(l => l.ForContext("Url", "https://a.example/" + Cr + Lf + "x").Information("delivered to {Url}"));

        Assert.Contains(@"delivered to https://a.example/\r\nx", text, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryHostPipeline_EscapesValuesBeforeTheyAreWritten()
    {
        // AddServiceDefaults is the one logging setup of every host; the providers it forwards to receive the
        // same enriched event the console sink renders.
        var capture = new CapturingProvider();
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings { EnvironmentName = "Test" });
        builder.AddServiceDefaults();
        builder.Services.AddSingleton<ILoggerProvider>(capture);
        using var host = builder.Build();

        host.Services.GetRequiredService<ILogger<LogForgingTests>>()
            .LogWarning("Webhook delivery to {Url} failed", "https://a.example/" + Lf + "[12:00:00 ERR -] forged");

        var message = Assert.Single(capture.Messages);
        Assert.DoesNotContain(Lf, message, StringComparison.Ordinal);
        Assert.Contains(@"https://a.example/\n[12:00:00 ERR -] forged", message, StringComparison.Ordinal);
    }

    private sealed class StringSink(MessageTemplateTextFormatter formatter) : ILogEventSink
    {
        private readonly StringWriter _writer = new();

        public string Text => _writer.ToString();

        public void Emit(LogEvent logEvent) => formatter.Format(logEvent, _writer);
    }

    private sealed class CapturingProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public Microsoft.Extensions.Logging.ILogger CreateLogger(string categoryName) => new Logger(Messages);

        public void Dispose() { }

        private sealed class Logger(ConcurrentQueue<string> messages) : Microsoft.Extensions.Logging.ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
    }
}
