using System.Globalization;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

/// <summary>
/// The Web cookie used to keep the roles from sign-in for eight sliding hours, so a removed
/// <c>admin</c> role kept opening admin pages. These pin that the cookie now asks the IdP again
/// once the interval passes, ends the session when the IdP refuses, and survives an IdP outage.
/// </summary>
public sealed class CookieRoleRevalidatorTests
{
    private const string TokenEndpoint = "https://idp.test/connect/token";
    private const string UserInfoEndpoint = "https://idp.test/connect/userinfo";

    private readonly FakeTimeProvider time = new(new DateTimeOffset(2026, 9, 14, 12, 0, 0, TimeSpan.Zero));
    private readonly FakeIdp idp = new();

    [Fact]
    public async Task NotDue_DoesNotCallTheIdp()
    {
        var context = CreateContext(checkedAt: time.GetUtcNow());
        time.Advance(TimeSpan.FromMinutes(4));

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.Equal(0, idp.TokenCalls);
        Assert.False(context.ShouldRenew);
        Assert.True(context.Principal!.IsInRole("admin"));
    }

    [Fact]
    public async Task Due_ReplacesRolesAndStoresRotatedTokens()
    {
        idp.UserInfoJson = """{"sub":"u1","name":"alice","preferred_username":"alice","given_name":"","role":["viewer"]}""";
        var context = CreateContext(checkedAt: time.GetUtcNow());
        time.Advance(TimeSpan.FromMinutes(5));

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.True(context.ShouldRenew);
        Assert.False(context.Principal!.IsInRole("admin"));
        Assert.True(context.Principal.IsInRole("viewer"));
        Assert.Equal("alice", context.Principal.Identity!.Name);
        Assert.Equal("u1", context.Principal.FindFirst("sub")!.Value);
        Assert.Null(context.Principal.FindFirst("given_name"));
        Assert.Equal("new-access", context.Properties.GetTokenValue("access_token"));
        Assert.Equal("new-refresh", context.Properties.GetTokenValue("refresh_token"));
        Assert.Equal(Stamp(time.GetUtcNow()), context.Properties.Items[CookieRoleRevalidator.CheckedAtItem]);
        Assert.Equal("Bearer new-access", idp.LastUserInfoAuthorization);
        Assert.Empty(SignOuts(context));
    }

    [Fact]
    public async Task LegacyCookieWithoutStamp_IsRevalidatedImmediately()
    {
        var context = CreateContext(checkedAt: null);

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.Equal(1, idp.TokenCalls);
    }

    [Theory]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.Unauthorized)]
    public async Task RefreshRefused_EndsTheSession(HttpStatusCode status)
    {
        idp.TokenStatus = status;
        var context = CreateContext(checkedAt: null);

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.Null(context.Principal);
        Assert.Equal([CookieAuthenticationDefaults.AuthenticationScheme], SignOuts(context));
    }

    [Fact]
    public async Task IdpUnavailable_KeepsThePrincipalAndRetriesLater()
    {
        idp.TokenStatus = HttpStatusCode.ServiceUnavailable;
        var context = CreateContext(checkedAt: null);

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.True(context.Principal!.IsInRole("admin"));
        Assert.False(context.ShouldRenew);
        Assert.False(context.Properties.Items.ContainsKey(CookieRoleRevalidator.CheckedAtItem));
        Assert.Empty(SignOuts(context));
    }

    [Fact]
    public async Task UserInfoUnavailable_StillWritesBackTheRotatedTokens()
    {
        idp.UserInfoStatus = HttpStatusCode.BadGateway;
        var context = CreateContext(checkedAt: null);

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.True(context.ShouldRenew);
        Assert.Equal("new-refresh", context.Properties.GetTokenValue("refresh_token"));
        Assert.True(context.Principal!.IsInRole("admin"));
        Assert.False(context.Properties.Items.ContainsKey(CookieRoleRevalidator.CheckedAtItem));
    }

    [Fact]
    public async Task MissingRefreshToken_EndsTheSession()
    {
        var context = CreateContext(checkedAt: null, refreshToken: null);

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.Null(context.Principal);
        Assert.Equal(0, idp.TokenCalls);
        Assert.Single(SignOuts(context));
    }

    [Fact]
    public async Task SigningIn_StampsANewSessionButKeepsAnExistingStamp()
    {
        var revalidator = CreateRevalidator();
        var fresh = new AuthenticationProperties();
        await revalidator.OnSigningInAsync(SigningIn(fresh));
        Assert.Equal(Stamp(time.GetUtcNow()), fresh.Items[CookieRoleRevalidator.CheckedAtItem]);

        var existing = new AuthenticationProperties();
        existing.Items[CookieRoleRevalidator.CheckedAtItem] = "kept";
        time.Advance(TimeSpan.FromMinutes(1));
        await revalidator.OnSigningInAsync(SigningIn(existing));
        Assert.Equal("kept", existing.Items[CookieRoleRevalidator.CheckedAtItem]);
    }

    [Fact]
    public async Task SameRefreshToken_IsRedeemedOnlyOnce()
    {
        var client = CreateTokenClient();

        var first = await client.RefreshAsync("old-refresh", CancellationToken.None);
        var second = await client.RefreshAsync("old-refresh", CancellationToken.None);

        Assert.Equal(1, idp.TokenCalls);
        Assert.Equal("new-refresh", second.RefreshToken);
        Assert.Same(first, second);
    }

    [Fact]
    public async Task Due_StampsPermissionClaims()
    {
        var context = CreateContext(checkedAt: time.GetUtcNow());
        time.Advance(TimeSpan.FromMinutes(5));

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.Equal(["settings.edit"],
            context.Principal!.FindAll(QertumWebClaims.Permission).Select(c => c.Value));
    }

    [Fact]
    public async Task MeAccessUnavailable_KeepsExistingPermissionClaims()
    {
        idp.MeAccessStatus = HttpStatusCode.InternalServerError;
        var context = CreateContext(checkedAt: time.GetUtcNow(), permissions: ["settings.edit"]);
        time.Advance(TimeSpan.FromMinutes(5));

        await CreateRevalidator().ValidatePrincipalAsync(context);

        Assert.Equal(["settings.edit"],
            context.Principal!.FindAll(QertumWebClaims.Permission).Select(c => c.Value));
    }

    private CookieRoleRevalidator CreateRevalidator() => new(
        CreateTokenClient(),
        new MeAccessClient(idp, NullLogger<MeAccessClient>.Instance),
        time,
        Options.Create(new RoleRevalidationOptions { Interval = TimeSpan.FromMinutes(5) }),
        NullLogger<CookieRoleRevalidator>.Instance);

    private OidcTokenClient CreateTokenClient()
    {
        var oidc = new OpenIdConnectOptions
        {
            ClientId = "qertum-web",
            Authority = "https://idp.test",
            Configuration = new OpenIdConnectConfiguration { TokenEndpoint = TokenEndpoint, UserInfoEndpoint = UserInfoEndpoint }
        };
        return new OidcTokenClient(new StaticOptionsMonitor<OpenIdConnectOptions>(oidc), idp, time, NullLogger<OidcTokenClient>.Instance);
    }

    private static CookieValidatePrincipalContext CreateContext(
        DateTimeOffset? checkedAt, string? refreshToken = "old-refresh", string[]? permissions = null)
    {
        var claims = new List<Claim> { new("sub", "u1"), new("name", "alice"), new("role", "admin") };
        claims.AddRange((permissions ?? []).Select(p => new Claim(QertumWebClaims.Permission, p)));
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme, "name", "role");

        var properties = new AuthenticationProperties();
        var tokens = new List<AuthenticationToken> { new() { Name = "access_token", Value = "old-access" } };
        if (refreshToken is not null)
            tokens.Add(new() { Name = "refresh_token", Value = refreshToken });
        properties.StoreTokens(tokens);
        if (checkedAt is { } stamp)
            properties.Items[CookieRoleRevalidator.CheckedAtItem] = Stamp(stamp);

        var httpContext = new DefaultHttpContext
        {
            RequestServices = new ServiceCollection().AddSingleton<IAuthenticationService, RecordingAuthenticationService>().BuildServiceProvider()
        };

        return new CookieValidatePrincipalContext(
            httpContext,
            new AuthenticationScheme(CookieAuthenticationDefaults.AuthenticationScheme, null, typeof(CookieAuthenticationHandler)),
            new CookieAuthenticationOptions(),
            new AuthenticationTicket(new ClaimsPrincipal(identity), properties, CookieAuthenticationDefaults.AuthenticationScheme));
    }

    private static CookieSigningInContext SigningIn(AuthenticationProperties properties) => new(
        new DefaultHttpContext(),
        new AuthenticationScheme(CookieAuthenticationDefaults.AuthenticationScheme, null, typeof(CookieAuthenticationHandler)),
        new CookieAuthenticationOptions(),
        new ClaimsPrincipal(new ClaimsIdentity()),
        properties,
        new CookieOptions());

    private static IReadOnlyList<string?> SignOuts(CookieValidatePrincipalContext context) =>
        ((RecordingAuthenticationService)context.HttpContext.RequestServices.GetRequiredService<IAuthenticationService>()).SignOuts;

    private static string Stamp(DateTimeOffset value) => value.ToString("o", CultureInfo.InvariantCulture);

    private sealed class FakeIdp : HttpMessageHandler, IHttpClientFactory
    {
        public HttpStatusCode TokenStatus { get; set; } = HttpStatusCode.OK;
        public HttpStatusCode UserInfoStatus { get; set; } = HttpStatusCode.OK;
        public HttpStatusCode MeAccessStatus { get; set; } = HttpStatusCode.OK;
        public string MeAccessJson { get; set; } = """{"roles":["admin"],"isAdmin":true,"permissions":[{"name":"settings.edit","description":"d","granted":true},{"name":"certificates.manage","description":"d","granted":false}]}""";
        public string UserInfoJson { get; set; } = """{"sub":"u1","name":"alice","role":["admin"]}""";
        public int TokenCalls { get; private set; }
        public string? LastUserInfoAuthorization { get; private set; }

        // The token client builds absolute URLs; the access client uses a relative path, so the
        // fake supplies a base address the same way the host's named client does.
        public HttpClient CreateClient(string name) =>
            new(this, disposeHandler: false) { BaseAddress = new Uri("https://api.test/") };

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.RequestUri!.AbsoluteUri == TokenEndpoint)
            {
                TokenCalls++;
                return Task.FromResult(new HttpResponseMessage(TokenStatus)
                {
                    Content = new StringContent("""{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}""")
                });
            }

            if (request.RequestUri.AbsolutePath == "/v1/me/access")
            {
                return Task.FromResult(new HttpResponseMessage(MeAccessStatus) { Content = new StringContent(MeAccessJson) });
            }

            LastUserInfoAuthorization = request.Headers.Authorization?.ToString();
            return Task.FromResult(new HttpResponseMessage(UserInfoStatus) { Content = new StringContent(UserInfoJson) });
        }
    }

    private sealed class RecordingAuthenticationService : IAuthenticationService
    {
        public List<string?> SignOuts { get; } = [];

        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties)
        {
            SignOuts.Add(scheme);
            return Task.CompletedTask;
        }

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => throw new NotSupportedException();
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties) => throw new NotSupportedException();
    }

    private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
    {
        public T CurrentValue => value;
        public T Get(string? name) => value;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}