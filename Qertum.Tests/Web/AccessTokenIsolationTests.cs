using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Qertum.Services;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

public sealed class AccessTokenIsolationTests
{
    private readonly RecordingTransport api = new();
    private readonly FakeIdp idp = new();
    private int transportCreations;

    [Fact]
    public async Task FactorySharedTransport_NeverUsesAnotherScopeToken()
    {
        using var root = BuildServices();
        using var scopeA = root.CreateScope();
        using var scopeB = root.CreateScope();
        var contextAccessor = root.GetRequiredService<IHttpContextAccessor>();
        var clientA = scopeA.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();
        var clientB = scopeB.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();
        SetAuthenticated(scopeA, "user-a", "access-a", "refresh-a", contextAccessor);

        await clientA.GetCaStatusAsync(TestContext.Current.CancellationToken);
        contextAccessor.HttpContext = null;
        await Assert.ThrowsAsync<ApiProblemException>(() =>
            clientB.GetCaStatusAsync(TestContext.Current.CancellationToken));

        Assert.Null(api.AuthHeaders[^1]);
        SetAuthenticated(scopeB, "user-b", "access-b", "refresh-b", contextAccessor);
        await clientB.GetCaStatusAsync(TestContext.Current.CancellationToken);
        contextAccessor.HttpContext = null;
        await clientA.GetCaStatusAsync(TestContext.Current.CancellationToken);

        Assert.Equal(["Bearer access-a", null, "Bearer access-b", "Bearer access-a"], api.AuthHeaders);
        Assert.Equal(1, transportCreations);
        Assert.Empty(idp.RedeemedTokens);
    }

    [Fact]
    public async Task UnauthorizedRefresh_RedeemsOnlyTheRequestingScopesRefreshToken()
    {
        api.RefuseToken = "Bearer access-a";
        using var root = BuildServices();
        using var scopeA = root.CreateScope();
        using var scopeB = root.CreateScope();
        var contextAccessor = root.GetRequiredService<IHttpContextAccessor>();
        var clientA = scopeA.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();
        var clientB = scopeB.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();
        SetAuthenticated(scopeA, "user-a", "access-a", "refresh-a", contextAccessor);
        SetAuthenticated(scopeB, "admin", "access-admin", "refresh-admin", contextAccessor);
        contextAccessor.HttpContext = null;

        await clientA.GetCaStatusAsync(TestContext.Current.CancellationToken);
        await clientB.GetCaStatusAsync(TestContext.Current.CancellationToken);

        Assert.Equal(["Bearer access-a", "Bearer new-a", "Bearer access-admin"], api.AuthHeaders);
        Assert.Equal(["refresh-a"], idp.RedeemedTokens);
    }

    [Fact]
    public async Task NoScopedToken_RemovesCallerSuppliedAuthorization()
    {
        var state = new TestAuthenticationStateProvider
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "user-a")], CookieAuthenticationDefaults.AuthenticationScheme))
        };
        using var handler = new AccessTokenHandler(new EmptyTokens(), state) { InnerHandler = api };
        using var client = new HttpClient(handler, disposeHandler: false);
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://api.test/v1/ca/status");
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "attacker");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(api.AuthHeaders[^1]);
    }

    [Fact]
    public async Task UnauthorizedRetry_PreservesRequestBodyHeadersOptionsAndVersion()
    {
        var transport = new ReplayTransport();
        var state = new TestAuthenticationStateProvider
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "user-a")], CookieAuthenticationDefaults.AuthenticationScheme))
        };
        using var handler = new AccessTokenHandler(new RotatingTokens(), state) { InnerHandler = transport };
        using var client = new HttpClient(handler);
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://api.test/v1/requests")
        {
            Content = new ByteArrayContent([1, 2, 3, 4]),
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower
        };
        request.Headers.TryAddWithoutValidation("X-Trace", "trace-a");
        request.Content.Headers.TryAddWithoutValidation("X-Content-Tag", "tag-a");
        request.Options.Set(new HttpRequestOptionsKey<string>("scope"), "user-a");

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(2, transport.Requests.Count);
        Assert.Equal(["Bearer access-a", "Bearer new-a"], transport.Requests.Select(r => r.Authorization));
        Assert.All(transport.Requests, recorded =>
        {
            Assert.Equal([1, 2, 3, 4], recorded.Body);
            Assert.Equal("tag-a", recorded.ContentTag);
            Assert.Equal("trace-a", recorded.Trace);
            Assert.Equal("user-a", recorded.Scope);
            Assert.Equal(HttpVersion.Version20, recorded.Version);
            Assert.Equal(HttpVersionPolicy.RequestVersionOrLower, recorded.VersionPolicy);
        });
    }

    [Fact]
    public async Task Forbidden_DoesNotRefreshOrRetry()
    {
        api.StatusOverride = HttpStatusCode.Forbidden;
        using var root = BuildServices();
        using var scope = root.CreateScope();
        SetAuthenticated(scope, "user-a", "access-a", "refresh-a",
            root.GetRequiredService<IHttpContextAccessor>());

        await Assert.ThrowsAsync<ApiProblemException>(() =>
            scope.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>()
                .GetCaStatusAsync(TestContext.Current.CancellationToken));

        Assert.Equal(["Bearer access-a"], api.AuthHeaders);
        Assert.Empty(idp.RedeemedTokens);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task FailedRefresh_DoesNotRetry(HttpStatusCode idpStatus)
    {
        api.RefuseToken = "Bearer access-a";
        idp.TokenStatus = idpStatus;
        using var root = BuildServices();
        using var scope = root.CreateScope();
        SetAuthenticated(scope, "user-a", "access-a", "refresh-a",
            root.GetRequiredService<IHttpContextAccessor>());

        await Assert.ThrowsAsync<ApiProblemException>(() =>
            scope.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>()
                .GetCaStatusAsync(TestContext.Current.CancellationToken));

        Assert.Equal(["Bearer access-a"], api.AuthHeaders);
        Assert.Equal(["refresh-a"], idp.RedeemedTokens);
    }

    [Fact]
    public async Task SecondUnauthorized_IsReturnedWithoutAnotherRefresh()
    {
        api.StatusOverride = HttpStatusCode.Unauthorized;
        using var root = BuildServices();
        using var scope = root.CreateScope();
        SetAuthenticated(scope, "user-a", "access-a", "refresh-a",
            root.GetRequiredService<IHttpContextAccessor>());

        await Assert.ThrowsAsync<ApiProblemException>(() =>
            scope.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>()
                .GetCaStatusAsync(TestContext.Current.CancellationToken));

        Assert.Equal(["Bearer access-a", "Bearer new-a"], api.AuthHeaders);
        Assert.Equal(["refresh-a"], idp.RedeemedTokens);
    }

    [Fact]
    public async Task ConcurrentUnauthorized_RedeemsOnceWithinOneScope()
    {
        api.RefuseToken = "Bearer access-a";
        api.HoldInitialUnauthorizedPair = true;
        using var root = BuildServices();
        using var scope = root.CreateScope();
        SetAuthenticated(scope, "user-a", "access-a", "refresh-a",
            root.GetRequiredService<IHttpContextAccessor>());
        var client = scope.ServiceProvider.GetRequiredService<CertificateRequestsApiClient>();

        await Task.WhenAll(client.GetCaStatusAsync(TestContext.Current.CancellationToken),
            client.GetCaStatusAsync(TestContext.Current.CancellationToken));

        Assert.Single(idp.RedeemedTokens);
        Assert.Equal(4, api.AuthHeaders.Count);
        Assert.Equal(2, api.AuthHeaders.Count(header => header == "Bearer new-a"));
    }

    [Fact]
    public async Task SignOutWhileFirstResponsePending_DoesNotRedeemOrRetry()
    {
        var transport = new PausedUnauthorizedTransport();
        var tokens = new CountingTokens();
        var state = new TestAuthenticationStateProvider
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "user-a")], CookieAuthenticationDefaults.AuthenticationScheme))
        };
        using var handler = new AccessTokenHandler(tokens, state) { InnerHandler = transport };
        using var client = new HttpClient(handler);
        var pending = client.GetAsync("https://api.test/v1/ca/status", TestContext.Current.CancellationToken);
        await transport.FirstRequestEntered.Task.WaitAsync(TestContext.Current.CancellationToken);

        state.User = new ClaimsPrincipal(new ClaimsIdentity());
        transport.ReleaseFirstResponse.TrySetResult();
        using var response = await pending;

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(0, tokens.RefreshCalls);
        Assert.Single(transport.Authorizations);
    }

    [Fact]
    public async Task SignOutWhileRefreshPending_DoesNotRetry()
    {
        var transport = new PausedUnauthorizedTransport();
        var tokens = new PausedRefreshTokens();
        var state = new TestAuthenticationStateProvider
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "user-a")], CookieAuthenticationDefaults.AuthenticationScheme))
        };
        using var handler = new AccessTokenHandler(tokens, state) { InnerHandler = transport };
        using var client = new HttpClient(handler);
        var pending = client.GetAsync("https://api.test/v1/ca/status", TestContext.Current.CancellationToken);
        await transport.FirstRequestEntered.Task.WaitAsync(TestContext.Current.CancellationToken);
        transport.ReleaseFirstResponse.TrySetResult();
        await tokens.RefreshEntered.Task.WaitAsync(TestContext.Current.CancellationToken);

        state.User = new ClaimsPrincipal(new ClaimsIdentity());
        tokens.ReleaseRefresh.TrySetResult();
        using var response = await pending;

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Single(transport.Authorizations);
    }

    [Fact]
    public async Task SignOutWhileInitialTokenPending_SendsWithoutBearer()
    {
        var transport = new RecordingTransport();
        var tokens = new PausedInitialTokens();
        var state = new TestAuthenticationStateProvider
        {
            User = new ClaimsPrincipal(new ClaimsIdentity(
                [new Claim("sub", "user-a")], CookieAuthenticationDefaults.AuthenticationScheme))
        };
        using var handler = new AccessTokenHandler(tokens, state) { InnerHandler = transport };
        using var client = new HttpClient(handler);
        var pending = client.GetAsync("https://api.test/v1/ca/status", TestContext.Current.CancellationToken);
        await tokens.TokenLookupEntered.Task.WaitAsync(TestContext.Current.CancellationToken);

        state.User = new ClaimsPrincipal(new ClaimsIdentity());
        tokens.ReleaseTokenLookup.TrySetResult();
        using var response = await pending;

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Null(Assert.Single(transport.AuthHeaders));
    }

    private sealed class PausedInitialTokens : ICircuitTokens
    {
        public TaskCompletionSource TokenLookupEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseTokenLookup { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public async Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default)
        {
            TokenLookupEntered.TrySetResult();
            await ReleaseTokenLookup.Task.WaitAsync(cancellationToken);
            return "access-a";
        }
        public Task<string?> RefreshAfterUnauthorizedAsync(string rejectedAccessToken,
            CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
    }

    private sealed class PausedRefreshTokens : ICircuitTokens
    {
        public TaskCompletionSource RefreshEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseRefresh { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>("access-a");
        public async Task<string?> RefreshAfterUnauthorizedAsync(string rejectedAccessToken,
            CancellationToken cancellationToken = default)
        {
            RefreshEntered.TrySetResult();
            await ReleaseRefresh.Task.WaitAsync(cancellationToken);
            return "new-a";
        }
    }

    private sealed class CountingTokens : ICircuitTokens
    {
        public int RefreshCalls { get; private set; }
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>("access-a");
        public Task<string?> RefreshAfterUnauthorizedAsync(string rejectedAccessToken,
            CancellationToken cancellationToken = default)
        {
            RefreshCalls++;
            return Task.FromResult<string?>("new-a");
        }
    }

    private sealed class PausedUnauthorizedTransport : HttpMessageHandler
    {
        public TaskCompletionSource FirstRequestEntered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseFirstResponse { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<string?> Authorizations { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Authorizations.Add(request.Headers.Authorization?.ToString());
            if (Authorizations.Count == 1)
            {
                FirstRequestEntered.TrySetResult();
                await ReleaseFirstResponse.Task.WaitAsync(cancellationToken);
            }
            return new HttpResponseMessage(HttpStatusCode.Unauthorized);
        }
    }

    private sealed class RotatingTokens : ICircuitTokens
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>("access-a");

        public Task<string?> RefreshAfterUnauthorizedAsync(string rejectedAccessToken,
            CancellationToken cancellationToken = default) => Task.FromResult<string?>("new-a");
    }

    private sealed class ReplayTransport : HttpMessageHandler
    {
        public List<(string? Authorization, byte[]? Body, string? ContentTag, string? Trace,
            string? Scope, Version Version, HttpVersionPolicy VersionPolicy)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            request.Options.TryGetValue(new HttpRequestOptionsKey<string>("scope"), out var scope);
            IEnumerable<string>? contentTag = null;
            request.Content?.Headers.TryGetValues("X-Content-Tag", out contentTag);
            request.Headers.TryGetValues("X-Trace", out var trace);
            Requests.Add((request.Headers.Authorization?.ToString(),
                request.Content is null ? null : await request.Content.ReadAsByteArrayAsync(cancellationToken),
                contentTag?.SingleOrDefault(), trace?.SingleOrDefault(), scope,
                request.Version, request.VersionPolicy));
            return new HttpResponseMessage(Requests.Count == 1 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK);
        }
    }

    private ServiceProvider BuildServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpContextAccessor();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<IConfiguration>(new ConfigurationBuilder().AddInMemoryCollection(
            new Dictionary<string, string?> { ["ApiService:BaseUrl"] = "https://api.test" }).Build());
        services.AddScoped<CircuitTokenAccessor>();
        services.AddScoped<ICircuitTokens>(sp => sp.GetRequiredService<CircuitTokenAccessor>());
        services.AddScoped<TestAuthenticationStateProvider>();
        services.AddScoped<AuthenticationStateProvider>(sp => sp.GetRequiredService<TestAuthenticationStateProvider>());
        services.AddSingleton<IOptionsMonitor<OpenIdConnectOptions>>(new StaticOptionsMonitor<OpenIdConnectOptions>(
            new OpenIdConnectOptions
            {
                ClientId = "qertum-web",
                Authority = "https://idp.test",
                Configuration = new OpenIdConnectConfiguration
                {
                    TokenEndpoint = "https://idp.test/connect/token",
                    UserInfoEndpoint = "https://idp.test/connect/userinfo"
                }
            }));
        services.AddSingleton<OidcTokenClient>();
        services.AddHttpClient(OidcTokenClient.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => idp);
        services.AddQertumWebApiClient()
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                Interlocked.Increment(ref transportCreations);
                return api;
            });
        return services.BuildServiceProvider();
    }

    private static void SetAuthenticated(IServiceScope scope, string subject, string access,
        string refresh, IHttpContextAccessor contextAccessor)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", subject)], CookieAuthenticationDefaults.AuthenticationScheme));
        scope.ServiceProvider.GetRequiredService<TestAuthenticationStateProvider>().User = principal;
        var properties = new AuthenticationProperties();
        properties.StoreTokens(
        [
            new AuthenticationToken { Name = "access_token", Value = access },
            new AuthenticationToken { Name = "refresh_token", Value = refresh },
            new AuthenticationToken { Name = "expires_at", Value = TimeProvider.System.GetUtcNow().AddHours(1).ToString("o") }
        ]);
        var ticket = new AuthenticationTicket(principal, properties, CookieAuthenticationDefaults.AuthenticationScheme);
        contextAccessor.HttpContext = new DefaultHttpContext
        {
            User = principal,
            RequestServices = new ServiceCollection()
                .AddSingleton<IAuthenticationService>(new TicketAuthenticationService(ticket))
                .BuildServiceProvider()
        };
        scope.ServiceProvider.GetRequiredService<CircuitTokenAccessor>()
            .CaptureAsync(TestContext.Current.CancellationToken).GetAwaiter().GetResult();
    }

    private sealed class TestAuthenticationStateProvider : AuthenticationStateProvider
    {
        public ClaimsPrincipal User { get; set; } = new(new ClaimsIdentity());
        public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
            Task.FromResult(new AuthenticationState(User));
    }

    private sealed class EmptyTokens : ICircuitTokens
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>(null);

        public Task<string?> RefreshAfterUnauthorizedAsync(string rejectedAccessToken,
            CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
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

    private sealed class RecordingTransport : HttpMessageHandler
    {
        public List<string?> AuthHeaders { get; } = [];
        public string? RefuseToken { get; set; }
        public HttpStatusCode? StatusOverride { get; set; }
        public bool HoldInitialUnauthorizedPair { get; set; }
        private readonly TaskCompletionSource pairArrived = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int initialUnauthorizedCount;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var auth = request.Headers.Authorization?.ToString();
            lock (AuthHeaders)
                AuthHeaders.Add(auth);
            if (HoldInitialUnauthorizedPair && auth == RefuseToken)
            {
                if (Interlocked.Increment(ref initialUnauthorizedCount) == 2)
                    pairArrived.TrySetResult();
                await pairArrived.Task.WaitAsync(cancellationToken);
            }
            var status = StatusOverride ?? (auth is null || auth == RefuseToken
                ? HttpStatusCode.Unauthorized : HttpStatusCode.OK);
            return new HttpResponseMessage(status)
            {
                Content = new StringContent(status != HttpStatusCode.OK
                    ? $$"""{"type":"about:blank","title":"{{status}}","status":{{(int)status}}}"""
                    : """{"isInitialized":true}""", System.Text.Encoding.UTF8,
                    status != HttpStatusCode.OK ? "application/problem+json" : "application/json")
            };
        }
    }

    private sealed class FakeIdp : HttpMessageHandler
    {
        public List<string> RedeemedTokens { get; } = [];
        public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var form = await request.Content!.ReadAsStringAsync(cancellationToken);
            var token = form.Split('&').Single(pair => pair.StartsWith("refresh_token=", StringComparison.Ordinal))
                .Split('=', 2)[1];
            lock (RedeemedTokens)
                RedeemedTokens.Add(Uri.UnescapeDataString(token));
            return new HttpResponseMessage(TokenStatus)
            {
                Content = new StringContent("""{"access_token":"new-a","refresh_token":"new-refresh-a","expires_in":3600}""")
            };
        }
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
