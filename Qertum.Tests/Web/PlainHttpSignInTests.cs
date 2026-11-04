using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Qertum.Web.Auth;

namespace Qertum.Tests.Web;

/// <summary>
/// Over plain http on a LAN address (the single-container default) every sign-in failed with "Correlation failed":
/// the correlation and nonce cookies were Secure, which a browser refuses from an http page. The error page then
/// asked for sign-in again, so the browser looped through the identity provider. https must stay as it was.
/// </summary>
public sealed class PlainHttpSignInTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 4, 9, 0, 0, TimeSpan.Zero);

    private static HttpContext Request(string scheme)
    {
        var context = new DefaultHttpContext();
        context.Request.Scheme = scheme;
        context.Request.Host = new HostString("198.51.100.109", 9080);
        return context;
    }

    private static OpenIdConnectOptions Configured()
    {
        var options = new OpenIdConnectOptions();
        PlainHttpSignIn.Configure(options);
        return options;
    }

    [Fact]
    public void OverHttp_TheCorrelationAndNonceCookiesAreNotSecure_AndLax()
    {
        var options = Configured();

        foreach (var builder in new[] { options.CorrelationCookie, options.NonceCookie })
        {
            var cookie = builder.Build(Request("http"), Now);
            Assert.False(cookie.Secure);
            Assert.Equal(SameSiteMode.Lax, cookie.SameSite);
            Assert.True(cookie.HttpOnly);
        }
    }

    [Fact]
    public void OverHttps_TheCookiesAreUnchanged()
    {
        var plain = new OpenIdConnectOptions();
        var options = Configured();

        foreach (var (wrapped, original) in new[] { (options.CorrelationCookie, plain.CorrelationCookie), (options.NonceCookie, plain.NonceCookie) })
        {
            var cookie = wrapped.Build(Request("https"), Now);
            var expected = original.Build(Request("https"), Now);
            Assert.True(cookie.Secure);
            Assert.Equal(SameSiteMode.None, cookie.SameSite);
            Assert.Equal(expected.Expires, cookie.Expires);
            Assert.Equal(expected.Path, cookie.Path);
        }
    }

    [Fact]
    public void TheCookieNamesAreTheHandlers()
    {
        var plain = new OpenIdConnectOptions();
        var options = Configured();

        Assert.Equal(plain.CorrelationCookie.Name, options.CorrelationCookie.Name);
        Assert.Equal(plain.NonceCookie.Name, options.NonceCookie.Name);
    }

    [Theory]
    [InlineData("http", OpenIdConnectResponseMode.Query)]
    [InlineData("https", OpenIdConnectResponseMode.FormPost)]
    public void TheResponseMode_IsQueryOnlyOverHttp(string scheme, string expected)
    {
        var context = new RedirectContext(Request(scheme), new AuthenticationScheme("oidc", null, typeof(OpenIdConnectHandler)),
            new OpenIdConnectOptions(), new AuthenticationProperties())
        {
            ProtocolMessage = new OpenIdConnectMessage { ResponseMode = OpenIdConnectResponseMode.FormPost },
        };

        PlainHttpSignIn.Apply(context);

        Assert.Equal(expected, context.ProtocolMessage.ResponseMode);
    }

    [Fact]
    public void TheErrorPage_IsOpenToEveryone()
    {
        var attributes = typeof(Qertum.Web.Components.Pages.Error).GetCustomAttributes(inherit: true);

        Assert.Contains(attributes, a => a is Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute);
    }
}
