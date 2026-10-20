using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Qertum.Services;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

/// <summary>
/// The cookie revalidator only runs on HTTP requests, so an open circuit kept its roles and
/// permissions until it reconnected. These pin the circuit-side rules.
/// </summary>
public sealed class CircuitRevalidationTests
{
    private sealed class StubAccess(Func<MeAccessResult> respond) : IMeAccess
    {
        public Task<MeAccessResult> GetAsync(string accessToken, CancellationToken cancellationToken = default)
            => Task.FromResult(respond());
    }

    private sealed class StubTokens(string? token) : ICircuitTokens
    {
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default) => Task.FromResult(token);

        public Task<string?> RefreshAfterUnauthorizedAsync(
            string rejectedAccessToken, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
    }

    private static ClaimsPrincipal Principal(params string[] permissions) =>
        new(new ClaimsIdentity(
            permissions.Select(p => new Claim(QertumWebClaims.Permission, p)).Append(new Claim("sub", "u1")),
            "Cookies", "name", "role"));

    private static MyAccessResponse Access(params string[] granted) => new()
    {
        Roles = ["ops"],
        IsAdmin = false,
        Permissions = AppPermissions.All.Select(p => new MyAccessPermission { Name = p, Description = "d", Granted = granted.Contains(p) }).ToList()
    };

    private static PermissionRevalidatingAuthenticationStateProvider Provider(IMeAccess access, ICircuitTokens tokens) =>
        new(access, tokens, Options.Create(new RoleRevalidationOptions()),
            new LoggerFactory(), NullLogger<PermissionRevalidatingAuthenticationStateProvider>.Instance);

    [Fact]
    public async Task Granted_RefreshesClaims()
    {
        var ct = TestContext.Current.CancellationToken;
        var provider = Provider(
            new StubAccess(() => new MeAccessResult(OidcCallOutcome.Success, Access(AppPermissions.CertificatesView))),
            new StubTokens("token"));

        var state = new AuthenticationState(Principal(AppPermissions.SettingsEdit));
        Assert.True(await provider.RevalidateForTestAsync(state, ct));

        Assert.Equal([AppPermissions.CertificatesView],
            provider.LastPrincipal!.FindAll(QertumWebClaims.Permission).Select(c => c.Value));
        Assert.True(provider.LastPrincipal.IsInRole("ops"));
    }

    [Fact]
    public async Task Rejected_EndsAuthentication()
    {
        var ct = TestContext.Current.CancellationToken;
        var provider = Provider(
            new StubAccess(() => new MeAccessResult(OidcCallOutcome.Rejected, null)),
            new StubTokens("token"));

        Assert.False(await provider.RevalidateForTestAsync(new AuthenticationState(Principal()), ct));
    }

    [Fact]
    public async Task Unavailable_KeepsThePrincipal()
    {
        var ct = TestContext.Current.CancellationToken;
        var provider = Provider(
            new StubAccess(() => new MeAccessResult(OidcCallOutcome.Unavailable, null)),
            new StubTokens("token"));

        Assert.True(await provider.RevalidateForTestAsync(new AuthenticationState(Principal(AppPermissions.SettingsEdit)), ct));
        Assert.Null(provider.LastPrincipal);
    }

    [Fact]
    public async Task NoUsableToken_EndsAuthentication()
    {
        var ct = TestContext.Current.CancellationToken;
        var provider = Provider(
            new StubAccess(() => new MeAccessResult(OidcCallOutcome.Success, Access())),
            new StubTokens(null));

        Assert.False(await provider.RevalidateForTestAsync(new AuthenticationState(Principal()), ct));
    }
}
