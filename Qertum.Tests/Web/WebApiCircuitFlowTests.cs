using System.Net;
using System.Security.Claims;
using Bunit;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Qertum.Services;
using Qertum.Web.Auth;
using Qertum.Web.Components.Layout;

namespace Qertum.Tests.Web;

public sealed class WebApiCircuitFlowTests
{
    [Fact]
    public async Task MainLayout_CapturesBeforeItsFirstApiCall()
    {
        await using var test = new BunitContext();
        var api = new SubjectRecordingTransport();
        ConfigureSignedInAdmin(test, api);

        test.Render<MainLayout>();

        Assert.Equal("Bearer access-admin", api.LastAuthorization);
        test.Services.GetRequiredService<IHttpContextAccessor>().HttpContext = null;
        await test.Services.GetRequiredService<CertificateRequestsApiClient>()
            .GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken);
        Assert.Equal("Bearer access-admin", api.LastAuthorization);
    }

    // /onboarding does not use MainLayout; without its own capture the circuit had no token and
    // "Generate" failed with 401 Unauthorized.
    [Fact]
    public async Task OnboardingLayout_CapturesTokensForCircuitCalls()
    {
        await using var test = new BunitContext();
        var api = new SubjectRecordingTransport();
        ConfigureSignedInAdmin(test, api);

        test.Render<OnboardingLayout>();

        test.Services.GetRequiredService<IHttpContextAccessor>().HttpContext = null;
        await test.Services.GetRequiredService<CertificateRequestsApiClient>()
            .GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken);
        Assert.Equal("Bearer access-admin", api.LastAuthorization);
    }

    private static void ConfigureSignedInAdmin(BunitContext test, SubjectRecordingTransport api)
    {
        var auth = test.AddAuthorization();
        auth.SetAuthorized("admin");
        auth.SetRoles("admin");
        test.Services.AddLogging();
        test.Services.AddHttpContextAccessor();
        test.Services.AddSingleton(TimeProvider.System);
        test.Services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ApiService:BaseUrl"] = "https://api.test",
                ["IdentityService:Authority"] = "https://idp.test"
            }).Build());
        test.Services.AddSingleton<IdentityAuthority>();
        test.Services.AddSingleton<IWebHostEnvironment>(new TestWebHostEnvironment());
        test.Services.AddScoped<CircuitTokenAccessor>();
        test.Services.AddScoped<IStepUpNotifier, StepUpNotifier>();
        test.Services.AddScoped<ICircuitTokens>(sp => sp.GetRequiredService<CircuitTokenAccessor>());
        test.Services.AddSingleton<IOptionsMonitor<OpenIdConnectOptions>>(new StaticOptionsMonitor<OpenIdConnectOptions>(
            new OpenIdConnectOptions { ClientId = "qertum-web", Authority = "https://idp.test" }));
        test.Services.AddSingleton<OidcTokenClient>();
        test.Services.AddHttpClient(OidcTokenClient.HttpClientName);
        test.Services.AddQertumWebApiClient().ConfigurePrimaryHttpMessageHandler(() => api);
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "admin"), new Claim("role", "admin")],
            CookieAuthenticationDefaults.AuthenticationScheme, "sub", "role"));
        var properties = new AuthenticationProperties();
        properties.StoreTokens(
        [
            new AuthenticationToken { Name = "access_token", Value = "access-admin" },
            new AuthenticationToken { Name = "refresh_token", Value = "refresh-admin" },
            new AuthenticationToken { Name = "expires_at", Value = DateTimeOffset.UtcNow.AddHours(1).ToString("o") }
        ]);
        test.Services.GetRequiredService<IHttpContextAccessor>().HttpContext = new DefaultHttpContext
        {
            User = principal,
            RequestServices = new ServiceCollection()
                .AddSingleton<IAuthenticationService>(new TicketAuthenticationService(
                    new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme)))
                .BuildServiceProvider()
        };
    }

    [Fact]
    public async Task CaptureThenContextFreeCallback_UsesOnlyTheCircuitAndStopsAfterSignOut()
    {
        var api = new SubjectRecordingTransport();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpContextAccessor();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["ApiService:BaseUrl"] = "https://api.test" }).Build());
        services.AddScoped<CircuitTokenAccessor>();
        services.AddScoped<ICircuitTokens>(sp => sp.GetRequiredService<CircuitTokenAccessor>());
        services.AddScoped<MutableAuthenticationState>();
        services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<MutableAuthenticationState>());
        services.AddSingleton<IOptionsMonitor<OpenIdConnectOptions>>(new StaticOptionsMonitor<OpenIdConnectOptions>(
            new OpenIdConnectOptions
            {
                ClientId = "qertum-web",
                Authority = "https://idp.test",
                Configuration = new OpenIdConnectConfiguration
                {
                    TokenEndpoint = "https://idp.test/connect/token"
                }
            }));
        services.AddSingleton<OidcTokenClient>();
        services.AddHttpClient(OidcTokenClient.HttpClientName);
        services.AddQertumWebApiClient().ConfigurePrimaryHttpMessageHandler(() => api);
        using var root = services.BuildServiceProvider();
        using var circuitA = root.CreateScope();
        using var circuitB = root.CreateScope();
        using var neverCaptured = root.CreateScope();
        var context = root.GetRequiredService<IHttpContextAccessor>();
        var clientA = circuitA.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();
        var clientB = circuitB.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();
        var clientMissing = neverCaptured.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();

        await CaptureAsync(circuitA, context, "user-a", "access-a");
        context.HttpContext = null;
        await clientA.GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken);
        Assert.Equal("Bearer access-a", api.LastAuthorization);

        await CaptureAsync(circuitB, context, "admin", "access-admin");
        context.HttpContext = null;
        await clientB.GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken);
        Assert.Equal("Bearer access-admin", api.LastAuthorization);
        await clientA.GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken);
        Assert.Equal("Bearer access-a", api.LastAuthorization);

        neverCaptured.ServiceProvider.GetRequiredService<MutableAuthenticationState>()
            .SetAuthenticated("new-user");
        await Assert.ThrowsAsync<ApiProblemException>(() =>
            clientMissing.GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken));
        Assert.Null(api.LastAuthorization);

        circuitA.ServiceProvider.GetRequiredService<MutableAuthenticationState>().SetAnonymous();
        await Assert.ThrowsAsync<ApiProblemException>(() =>
            clientA.GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken));
        Assert.Null(api.LastAuthorization);

        using var reconnected = root.CreateScope();
        context.HttpContext = AnonymousContext();
        await reconnected.ServiceProvider.GetRequiredService<CircuitTokenAccessor>()
            .CaptureAsync(Xunit.TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ApiProblemException>(() =>
            reconnected.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>()
                .GetCaStatusAsync(Xunit.TestContext.Current.CancellationToken));
        Assert.Null(api.LastAuthorization);
    }

    private static async Task CaptureAsync(IServiceScope scope, IHttpContextAccessor context,
        string subject, string access)
    {
        var principal = scope.ServiceProvider.GetRequiredService<MutableAuthenticationState>()
            .SetAuthenticated(subject);
        var properties = new AuthenticationProperties();
        properties.StoreTokens(
        [
            new AuthenticationToken { Name = "access_token", Value = access },
            new AuthenticationToken { Name = "refresh_token", Value = $"refresh-{subject}" },
            new AuthenticationToken { Name = "expires_at", Value = DateTimeOffset.UtcNow.AddHours(1).ToString("o") }
        ]);
        context.HttpContext = new DefaultHttpContext
        {
            User = principal,
            RequestServices = new ServiceCollection()
                .AddSingleton<IAuthenticationService>(new TicketAuthenticationService(
                    new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme)))
                .BuildServiceProvider()
        };
        await scope.ServiceProvider.GetRequiredService<CircuitTokenAccessor>()
            .CaptureAsync(Xunit.TestContext.Current.CancellationToken);
    }

    private static DefaultHttpContext AnonymousContext() => new()
    {
        User = new ClaimsPrincipal(new ClaimsIdentity())
    };

    private sealed class MutableAuthenticationState : AuthenticationStateProvider
    {
        private ClaimsPrincipal user = new(new ClaimsIdentity());

        public ClaimsPrincipal SetAuthenticated(string subject)
        {
            user = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", subject)], CookieAuthenticationDefaults.AuthenticationScheme));
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
            return user;
        }

        public void SetAnonymous()
        {
            user = new ClaimsPrincipal(new ClaimsIdentity());
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }

        public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
            Task.FromResult(new AuthenticationState(user));
    }

    private sealed class SubjectRecordingTransport : HttpMessageHandler
    {
        public string? LastAuthorization { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            LastAuthorization = request.Headers.Authorization?.ToString();
            var authorized = LastAuthorization is not null;
            return Task.FromResult(new HttpResponseMessage(authorized ? HttpStatusCode.OK : HttpStatusCode.Unauthorized)
            {
                Content = new StringContent(authorized
                    ? """{"isInitialized":true}"""
                    : """{"type":"about:blank","title":"Unauthorized","status":401}""",
                    System.Text.Encoding.UTF8, authorized ? "application/json" : "application/problem+json")
            });
        }
    }

    private sealed class TicketAuthenticationService(AuthenticationTicket ticket) : IAuthenticationService
    {
        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(AuthenticateResult.Success(ticket));
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            throw new NotSupportedException();
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            throw new NotSupportedException();
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal,
            AuthenticationProperties? properties) => Task.CompletedTask;
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            Task.CompletedTask;
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class TestWebHostEnvironment : IWebHostEnvironment
    {
        public string EnvironmentName { get; set; } = "Development";
        public string ApplicationName { get; set; } = "Qertum.Web";
        public string WebRootPath { get; set; } = ".";
        public IFileProvider WebRootFileProvider { get; set; } = new NullFileProvider();
        public string ContentRootPath { get; set; } = ".";
        public IFileProvider ContentRootFileProvider { get; set; } = new NullFileProvider();
    }
}
