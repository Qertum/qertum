using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

namespace Microsoft.Extensions.Hosting;

/// <summary>
/// The response headers every Qertum host sends, and the Content-Security-Policy of each. They cost nothing
/// on the API and protocol hosts; on the Web and identity pages they close content sniffing, framing by
/// another site (clickjacking a sign-in or an approval) and, through the full policies, script from anywhere
/// but the host itself. Every policy lives in this file, so they never disagree.
/// </summary>
public static class SecurityHeaders
{
    /// <summary>The policy of hosts that serve no pages (API, ACME, EST): only framing is refused.</summary>
    public const string FrameAncestorsOnly = "frame-ancestors 'none'";

    /// <summary>
    /// The SHA-256 of OpenIddict's <c>form_post</c> auto-submit script (<c>document.form.submit();</c>), the one
    /// inline script the identity service sends: without it a sign-in would stop at a "click here" button.
    /// <c>IdentityContentSecurityPolicyTests</c> checks it against a real response, so an OpenIddict upgrade
    /// that changes the script fails there.
    /// </summary>
    public const string OpenIddictFormPostScriptHash = "sha256-j7OoGArf6XW6YY4cAyS3riSSvrJRqpSi1fOF9vQ5SrI=";

    /// <summary>
    /// The identity service's policy. No <c>form-action</c>: <c>form_post</c> answers post to each client's own
    /// redirect address, which this host does not list.
    /// </summary>
    public const string IdentityPolicy =
        "default-src 'self'; " +
        $"script-src 'self' '{OpenIddictFormPostScriptHash}'; " +
        // Inline style attributes: the hand-written pages carry a few, and they cannot run code.
        "style-src 'self' 'unsafe-inline'; " +
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
        "object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

    /// <summary>
    /// The web UI's policy. Scripts only from the host itself (Blazor and <c>js/app.js</c>, never inline).
    /// Inline styles are allowed because Blazor writes <c>style</c> attributes while it renders (progress
    /// bars), and styles cannot run code. <paramref name="identityAuthority"/> is the browser-facing OIDC
    /// authority: sign-out posts to the web UI, which redirects to it, and browsers apply
    /// <c>form-action</c> to that redirect.
    /// </summary>
    public static string WebPolicy(string? identityAuthority)
    {
        var identityOrigin = Uri.TryCreate(identityAuthority, UriKind.Absolute, out var uri)
            ? " " + uri.GetLeftPart(UriPartial.Authority)
            : "";
        return "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
               "img-src 'self' data:; font-src 'self'; connect-src 'self'; " +
               $"object-src 'none'; base-uri 'self'; form-action 'self'{identityOrigin}; frame-ancestors 'none'";
    }

    /// <summary>
    /// Adds the headers to every response, written when the response starts so error pages (whose
    /// handler clears the headers first) carry them too. Call it first, before any other middleware.
    /// </summary>
    /// <param name="app">The host's pipeline.</param>
    /// <param name="contentSecurityPolicy">The host's policy: <see cref="FrameAncestorsOnly"/> unless it serves pages.</param>
    public static IApplicationBuilder UseQertumSecurityHeaders(
        this IApplicationBuilder app, string contentSecurityPolicy = FrameAncestorsOnly) =>
        app.Use((context, next) =>
        {
            context.Response.OnStarting(static state =>
            {
                var (response, policy) = ((HttpResponse, string))state;
                var headers = response.Headers;
                headers.XContentTypeOptions = "nosniff";
                // URLs can carry ids and, in OIDC flows, state; nothing in Qertum needs the Referer.
                headers["Referrer-Policy"] = "no-referrer";
                // Replaces the SAMEORIGIN antiforgery writes: nothing in Qertum frames its own pages.
                headers.XFrameOptions = "DENY";
                headers.ContentSecurityPolicy = policy;
                return Task.CompletedTask;
            }, (context.Response, contentSecurityPolicy));
            return next(context);
        });
}
