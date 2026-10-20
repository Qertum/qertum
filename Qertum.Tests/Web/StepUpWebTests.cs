using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Qertum.Services;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

public sealed class StepUpWebTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private const string Header =
        "Bearer error=\"insufficient_user_authentication\", acr_values=\"mfa\", max_age=\"300\"";

    [Fact]
    public async Task AChallenge_RaisesTheNotifierOnce_AndIsNotTreatedAsAnExpiredToken()
    {
        var tokens = new Tokens();
        var notifier = new StepUpNotifier();
        var raised = new List<StepUpChallenge>();
        notifier.Required += raised.Add;
        var response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
        response.Headers.TryAddWithoutValidation("WWW-Authenticate", Header);
        var handler = new AccessTokenHandler(tokens, new SignedIn(), notifier) { InnerHandler = new Inner(response) };

        using var client = new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") };
        var result = await client.GetAsync("v1/anything", Ct);

        Assert.Equal(HttpStatusCode.Unauthorized, result.StatusCode);
        Assert.Equal([new StepUpChallenge("mfa", 300)], raised);
        Assert.Equal(0, tokens.Refreshes);
    }

    [Fact]
    public async Task AnOrdinary401_StillTriesARefresh_AndRaisesNothing()
    {
        var tokens = new Tokens();
        var notifier = new StepUpNotifier();
        var raised = 0;
        notifier.Required += _ => raised++;
        var handler = new AccessTokenHandler(tokens, new SignedIn(), notifier)
            { InnerHandler = new Inner(new HttpResponseMessage(HttpStatusCode.Unauthorized)) };

        using var client = new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") };
        await client.GetAsync("v1/anything", Ct);

        Assert.Equal(0, raised);
        Assert.Equal(1, tokens.Refreshes);
    }

    [Fact]
    public void TheRedirectUrl_CarriesTheReturnPageAndTheChallenge()
    {
        var url = StepUpRedirect.BuildUrl("/certificates/7?tab=keys", new StepUpChallenge("mfa", 300));

        Assert.Equal("/auth/step-up?returnUrl=%2Fcertificates%2F7%3Ftab%3Dkeys&acr_values=mfa&max_age=300", url);
    }

    [Fact]
    public void TheRedirectUrl_OmitsWhatTheChallengeDidNotSay()
    {
        Assert.Equal("/auth/step-up?returnUrl=%2F", StepUpRedirect.BuildUrl("/", new StepUpChallenge(null, null)));
    }

    [Theory]
    [InlineData("/", true)]
    [InlineData("/issuers?x=1", true)]
    [InlineData("//evil.example", false)]
    [InlineData("/\\evil.example", false)]
    [InlineData("https://evil.example/", false)]
    [InlineData("evil", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void OnlyLocalPathsAreAcceptedAsReturnUrls(string? url, bool expected) =>
        Assert.Equal(expected, StepUpRedirect.IsSafeReturnUrl(url));

    [Theory]
    [InlineData("mfa", true)]
    [InlineData("urn:okta:loa:2fa:any", true)]
    [InlineData("a b", true)]
    [InlineData("mfa&prompt=none", false)]
    [InlineData("mfa\r\nX: y", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void AcrValues_AreCheckedForSafeCharacters(string? value, bool expected) =>
        Assert.Equal(expected, StepUpRedirect.IsAcceptableAcrValues(value));

    [Theory]
    [InlineData(1, true)]
    [InlineData(86400, true)]
    [InlineData(0, false)]
    [InlineData(86401, false)]
    [InlineData(null, false)]
    public void MaxAge_MustBeBetweenOneSecondAndADay(int? value, bool expected) =>
        Assert.Equal(expected, StepUpRedirect.IsAcceptableMaxAge(value));

    [Theory]
    [InlineData("/issuers", "/issuers?qertum_stepup=1792014295")]
    [InlineData("/certificates/7?tab=keys", "/certificates/7?tab=keys&qertum_stepup=1792014295")]
    public void TheReturnUrl_GetsATimestampMarker_SoALoopCanBeRecognised(string url, string expected) =>
        Assert.Equal(expected, StepUpRedirect.WithMarker(url, DateTimeOffset.FromUnixTimeSeconds(1792014295)));

    [Fact]
    public void ComingBackFromAStepUpWithinAMinute_IsRecognised_AndNotAfterwards()
    {
        var marked = StepUpRedirect.WithMarker("/issuers", DateTimeOffset.FromUnixTimeSeconds(1_000_000));

        Assert.True(StepUpRedirect.CameBackRecently("https://qertum.test" + marked, DateTimeOffset.FromUnixTimeSeconds(1_000_000)));
        Assert.True(StepUpRedirect.CameBackRecently(marked, DateTimeOffset.FromUnixTimeSeconds(1_000_060)));
        Assert.False(StepUpRedirect.CameBackRecently(marked, DateTimeOffset.FromUnixTimeSeconds(1_000_061)));
    }

    [Theory]
    [InlineData("/issuers")]
    [InlineData("/issuers?qertum_stepup=soon")]
    [InlineData("/issuers?qertum_stepup=")]
    [InlineData("/issuers?qertum_stepup=9999999999")]
    [InlineData("/issuers?qertum_stepup=-5")]
    public void NoMarker_AGarbageMarker_OrAFutureOne_IsNotARecentStepUp(string url) =>
        Assert.False(StepUpRedirect.CameBackRecently(url, DateTimeOffset.FromUnixTimeSeconds(1_000_000)));

    [Fact]
    public void TheOidcRedirect_GetsAcrValuesAndMaxAge_FromTheAuthenticationProperties()
    {
        var properties = new AuthenticationProperties();
        properties.Items[StepUpRedirect.AcrItem] = "mfa";
        properties.Items[StepUpRedirect.MaxAgeItem] = "300";
        var context = Redirect(properties);

        StepUpRedirect.Apply(context);

        Assert.Equal("mfa", context.ProtocolMessage.AcrValues);
        Assert.Equal("300", context.ProtocolMessage.MaxAge);
    }

    [Fact]
    public void AnOrdinarySignIn_IsLeftAlone()
    {
        var context = Redirect(new AuthenticationProperties());

        StepUpRedirect.Apply(context);

        Assert.Null(context.ProtocolMessage.AcrValues);
        Assert.Null(context.ProtocolMessage.MaxAge);
    }

    private static RedirectContext Redirect(AuthenticationProperties properties) =>
        new(new DefaultHttpContext(), new AuthenticationScheme("oidc", null, typeof(OpenIdConnectHandler)), new OpenIdConnectOptions(), properties)
        {
            ProtocolMessage = new OpenIdConnectMessage()
        };

    private sealed class Tokens : ICircuitTokens
    {
        public int Refreshes { get; private set; }
        public Task<string?> GetAccessTokenAsync(CancellationToken cancellationToken = default) => Task.FromResult<string?>("token");

        public Task<string?> RefreshAfterUnauthorizedAsync(string rejectedAccessToken, CancellationToken cancellationToken = default)
        {
            Refreshes++;
            return Task.FromResult<string?>("replacement");
        }
    }

    private sealed class SignedIn : AuthenticationStateProvider
    {
        public override Task<AuthenticationState> GetAuthenticationStateAsync() =>
            Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity([new Claim("name", "alice")], "test"))));
    }

    private sealed class Inner(HttpResponseMessage response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response);
    }
}
