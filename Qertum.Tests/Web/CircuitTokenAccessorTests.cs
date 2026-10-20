using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

public sealed class CircuitTokenAccessorTests
{
    private readonly FakeTimeProvider time = new(new DateTimeOffset(2026, 9, 23, 12, 0, 0, TimeSpan.Zero));
    private readonly HttpContextAccessor contextAccessor = new();
    private readonly RecordingAuthenticationService authenticationService = new();
    private readonly FakeIdp idp = new();

    [Fact]
    public async Task MissingAccessToken_NeverRedeemsRefreshToken()
    {
        var tokens = await CreateAccessorAsync(null, "refresh-a");

        Assert.Null(await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Null(await tokens.RefreshAfterUnauthorizedAsync("missing", TestContext.Current.CancellationToken));
        Assert.Equal(0, idp.TokenCalls);
    }

    [Fact]
    public async Task ConcurrentUnauthorizedCalls_RedeemOnce()
    {
        var tokens = await CreateAccessorAsync("old-a", "refresh-a");

        var results = await Task.WhenAll(
            tokens.RefreshAfterUnauthorizedAsync("old-a", TestContext.Current.CancellationToken),
            tokens.RefreshAfterUnauthorizedAsync("old-a", TestContext.Current.CancellationToken));

        Assert.Equal(["new-a", "new-a"], results);
        Assert.Equal(1, idp.TokenCalls);
    }

    [Fact]
    public async Task AnonymousCapture_ClearsPriorTokens()
    {
        var tokens = await CreateAccessorAsync("old-a", "refresh-a");
        contextAccessor.HttpContext = CreateContext(null, null, authenticated: false);

        await tokens.CaptureAsync(TestContext.Current.CancellationToken);

        Assert.Null(await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal(0, idp.TokenCalls);
    }

    [Fact]
    public async Task ContextFreeCapture_PreservesOnlyThisScopesTokens()
    {
        var tokens = await CreateAccessorAsync("old-a", "refresh-a");
        contextAccessor.HttpContext = null;

        await tokens.CaptureAsync(TestContext.Current.CancellationToken);

        Assert.Equal("old-a", await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RejectedRefresh_ClearsAccessAndRefresh()
    {
        var tokens = await CreateAccessorAsync("old-a", "refresh-a");
        contextAccessor.HttpContext = CreateContext("old-a", "refresh-a");
        idp.TokenStatus = HttpStatusCode.BadRequest;

        Assert.Null(await tokens.RefreshAfterUnauthorizedAsync("old-a", TestContext.Current.CancellationToken));
        Assert.Null(await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal(1, idp.TokenCalls);
        Assert.Equal([CookieAuthenticationDefaults.AuthenticationScheme], authenticationService.SignOuts);
    }

    [Fact]
    public async Task NearExpiryRefresh_WritesRotatedTokensToItsOwnOpenSsrCookie()
    {
        var tokens = await CreateAccessorAsync("old-a", "refresh-a", TimeSpan.FromMinutes(2));
        contextAccessor.HttpContext = CreateContext("old-a", "refresh-a", expiresIn: TimeSpan.FromMinutes(2));

        Assert.Equal("new-a", await tokens.GetAccessTokenAsync(TestContext.Current.CancellationToken));
        Assert.Equal("new-a", authenticationService.LastSignInProperties!.GetTokenValue("access_token"));
        Assert.Equal("new-refresh-a", authenticationService.LastSignInProperties!.GetTokenValue("refresh_token"));
        Assert.Equal(1, idp.TokenCalls);
    }

    private async Task<CircuitTokenAccessor> CreateAccessorAsync(
        string? access, string? refresh, TimeSpan? expiresIn = null)
    {
        contextAccessor.HttpContext = CreateContext(access, refresh, expiresIn: expiresIn);
        var options = new OpenIdConnectOptions
        {
            ClientId = "qertum-web",
            Authority = "https://idp.test",
            Configuration = new OpenIdConnectConfiguration
            {
                TokenEndpoint = "https://idp.test/connect/token",
                UserInfoEndpoint = "https://idp.test/connect/userinfo"
            }
        };
        var tokenClient = new OidcTokenClient(new StaticOptionsMonitor<OpenIdConnectOptions>(options),
            idp, time, NullLogger<OidcTokenClient>.Instance);
        var accessor = new CircuitTokenAccessor(contextAccessor, tokenClient, time,
            NullLogger<CircuitTokenAccessor>.Instance);
        await accessor.CaptureAsync(TestContext.Current.CancellationToken);
        return accessor;
    }

    private HttpContext CreateContext(string? access, string? refresh, bool authenticated = true,
        TimeSpan? expiresIn = null)
    {
        var properties = new AuthenticationProperties();
        var values = new List<AuthenticationToken>();
        if (access is not null)
            values.Add(new AuthenticationToken { Name = "access_token", Value = access });
        if (refresh is not null)
            values.Add(new AuthenticationToken { Name = "refresh_token", Value = refresh });
        values.Add(new AuthenticationToken
        {
            Name = "expires_at",
            Value = time.GetUtcNow().Add(expiresIn ?? TimeSpan.FromHours(1)).ToString("o")
        });
        properties.StoreTokens(values);
        var identity = authenticated
            ? new ClaimsIdentity([new Claim("sub", "user-a")], CookieAuthenticationDefaults.AuthenticationScheme)
            : new ClaimsIdentity();
        authenticationService.Ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), properties,
            CookieAuthenticationDefaults.AuthenticationScheme);
        return new DefaultHttpContext
        {
            User = new ClaimsPrincipal(identity),
            RequestServices = new ServiceCollection()
                .AddSingleton<IAuthenticationService>(authenticationService)
                .BuildServiceProvider()
        };
    }

    private sealed class RecordingAuthenticationService : IAuthenticationService
    {
        public AuthenticationTicket? Ticket { get; set; }
        public AuthenticationProperties? LastSignInProperties { get; private set; }
        public List<string?> SignOuts { get; } = [];

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) =>
            Task.FromResult(Ticket is null ? AuthenticateResult.NoResult() : AuthenticateResult.Success(Ticket));

        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal,
            AuthenticationProperties? properties)
        {
            LastSignInProperties = properties;
            return Task.CompletedTask;
        }

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignOuts.Add(scheme);
            return Task.CompletedTask;
        }

        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            throw new NotSupportedException();

        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) =>
            throw new NotSupportedException();
    }

    private sealed class FakeIdp : HttpMessageHandler, IHttpClientFactory
    {
        private int tokenCalls;
        public int TokenCalls => tokenCalls;
        public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;

        public HttpClient CreateClient(string name) => new(this, disposeHandler: false);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref tokenCalls);
            return Task.FromResult(new HttpResponseMessage(TokenStatus)
            {
                Content = new StringContent("""{"access_token":"new-a","refresh_token":"new-refresh-a","expires_in":3600}""")
            });
        }
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
