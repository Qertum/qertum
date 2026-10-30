using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Qertum.ServiceDefaults;

namespace Qertum.Tests;

/// <summary>A host whose public address is plain http says so at startup; https, Development and junk stay quiet.</summary>
public sealed class InsecureTransportTests
{
    private sealed class Capture : ILogger
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }

    private sealed class Env(string name) : IHostEnvironment
    {
        public string EnvironmentName { get; set; } = name;
        public string ApplicationName { get; set; } = "test";
        public string ContentRootPath { get; set; } = "/";
        public Microsoft.Extensions.FileProviders.IFileProvider ContentRootFileProvider { get; set; } = null!;
    }

    [Fact]
    public void PlainHttpOutsideDevelopment_Warns_AndNamesTheServiceAndTheUrl()
    {
        var log = new Capture();

        var warned = InsecureTransport.WarnIfPlainHttp(log, new Env("Production"), "ApiService", "http://ca.example.com:8081");

        Assert.True(warned);
        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("ApiService", entry.Message);
        Assert.Contains("http://ca.example.com:8081", entry.Message);
        Assert.Contains("unencrypted", entry.Message);
    }

    [Theory]
    [InlineData("Production", "https://ca.example.com:8081")]
    [InlineData("Development", "http://localhost:5000")]
    [InlineData("Production", "")]
    [InlineData("Production", null)]
    [InlineData("Production", "not a url")]
    public void HttpsDevelopmentAndUnusableValues_StayQuiet(string environment, string? url)
    {
        var log = new Capture();

        var warned = InsecureTransport.WarnIfPlainHttp(log, new Env(environment), "Web", url);

        Assert.False(warned);
        Assert.Empty(log.Entries);
    }
}
