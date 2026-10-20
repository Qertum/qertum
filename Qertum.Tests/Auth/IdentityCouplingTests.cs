using System.Net;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Qertum.Services;
using Qertum.Services.Auth;

namespace Qertum.Tests.Auth;

public sealed class IdentityCouplingTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static IdentityServiceHealthCheck HealthCheck(Dictionary<string, string?> settings, List<Uri> requested)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(settings).Build();
        return new IdentityServiceHealthCheck(new FactoryOver(requested), configuration);
    }

    [Fact]
    public async Task TheHealthCheck_ProbesTheConfiguredIdentityAuthority_BeforeAnyOtherSetting()
    {
        var requested = new List<Uri>();
        var check = HealthCheck(new()
        {
            ["Identity:Authority"] = "https://idp.example/realms/qertum/",
            ["Services:identityservice:https:0"] = "https://aspire.local",
            ["IdentityService:Authority"] = "https://legacy.local"
        }, requested);

        await check.CheckHealthAsync(new(), Ct);

        Assert.Equal(["https://idp.example/realms/qertum/.well-known/openid-configuration"], requested.Select(u => u.ToString()));
    }

    [Fact]
    public async Task TheHealthCheck_StillFallsBackToServiceDiscovery_WhenNoAuthorityIsConfigured()
    {
        var requested = new List<Uri>();
        var check = HealthCheck(new() { ["Services:identityservice:https:0"] = "https://aspire.local" }, requested);

        await check.CheckHealthAsync(new(), Ct);

        Assert.Equal("https://aspire.local/.well-known/openid-configuration", requested.Single().ToString());
    }

    [Fact]
    public async Task AnIssuerMismatch_IsLogged_WithBothStrings_AndNoToken()
    {
        var logs = new CapturingLoggerProvider();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(logs));
        services.AddQertumJwtAuthentication(
            new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Identity:Authority"] = "https://idp.example/realms/qertum", ["Identity:Audience"] = "qertum-api"
            }).Build(), isDevelopment: false);
        await using var provider = services.BuildServiceProvider();
        var options = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>().Get(JwtBearerDefaults.AuthenticationScheme);
        var http = new DefaultHttpContext { RequestServices = provider };
        var failed = new AuthenticationFailedContext(http, new AuthenticationScheme("Bearer", null, typeof(JwtBearerHandler)), options)
        {
            Exception = new SecurityTokenInvalidIssuerException("bad issuer") { InvalidIssuer = "http://localhost:8080/realms/qertum" }
        };

        await options.Events.OnAuthenticationFailed(failed);

        var line = Assert.Single(logs.Messages, m => m.Contains("Identity:Authority"));
        Assert.Contains("http://localhost:8080/realms/qertum", line);
        Assert.Contains("https://idp.example/realms/qertum", line);
    }

    private sealed class FactoryOver(List<Uri> requested) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new Recording(requested));
    }

    private sealed class Recording(List<Uri> requested) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            requested.Add(request.RequestUri!);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public List<string> Messages { get; } = [];
        public ILogger CreateLogger(string categoryName) => new Capture(Messages);
        public void Dispose() { }

        private sealed class Capture(List<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
                messages.Add(formatter(state, exception));
        }
    }
}
