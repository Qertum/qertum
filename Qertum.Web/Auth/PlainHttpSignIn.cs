using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace Qertum.Web.Auth;

/// <summary>
/// Lets sign-in work when the web UI is reached over plain http on an address other than localhost (the
/// single-container default on a LAN, <c>http://192.168.1.50:8080</c>). ASP.NET writes the OIDC correlation and
/// nonce cookies <c>Secure; SameSite=None</c>, and a browser refuses a <c>Secure</c> cookie from an http page, so
/// the callback always failed with "Correlation failed". On an http request the two cookies are written without
/// <c>Secure</c> and with <c>SameSite=Lax</c> (<c>None</c> without <c>Secure</c> is refused too), and the
/// authorization response comes back as a query redirect rather than a <c>form_post</c>, because a Lax cookie
/// travels with a top-level GET from another site but not with a POST. An https request is left exactly as before.
/// </summary>
public static class PlainHttpSignIn
{
    /// <summary>Wraps the correlation and nonce cookie builders of <paramref name="options"/>.</summary>
    /// <param name="options">The web host's OpenID Connect options.</param>
    public static void Configure(OpenIdConnectOptions options)
    {
        options.CorrelationCookie = new SchemeAwareCookieBuilder(options.CorrelationCookie);
        options.NonceCookie = new SchemeAwareCookieBuilder(options.NonceCookie);
    }

    /// <summary>On an http request, asks for the authorization response as a query redirect.</summary>
    /// <param name="context">The redirect to the identity provider.</param>
    public static void Apply(RedirectContext context)
    {
        if (!context.Request.IsHttps)
            context.ProtocolMessage.ResponseMode = OpenIdConnectResponseMode.Query;
    }

    /// <summary>
    /// The handler's own builder (name, path, lifetime), with <c>Secure</c> and <c>SameSite</c> chosen per request.
    /// </summary>
    internal sealed class SchemeAwareCookieBuilder(CookieBuilder inner) : CookieBuilder
    {
        /// <inheritdoc />
        public override string? Name
        {
            get => inner.Name;
            set => inner.Name = value;
        }

        /// <inheritdoc />
        public override CookieOptions Build(HttpContext context, DateTimeOffset expiresFrom)
        {
            var options = inner.Build(context, expiresFrom);
            if (!context.Request.IsHttps)
            {
                options.Secure = false;
                options.SameSite = SameSiteMode.Lax;
            }
            return options;
        }
    }
}
