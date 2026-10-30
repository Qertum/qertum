using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;

namespace Qertum.Tests;

public sealed class SecurityHeadersTests
{
    private static readonly string[] Hosts =
        ["Qertum.ApiService", "Qertum.AcmeService", "Qertum.EstService", "Qertum.Web", "Qertum.IdentityService"];

    [Fact]
    public async Task EveryResponse_CarriesTheHeaders()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync(app => app.MapGet("/", () => "ok"), ct);

        var response = await app.GetTestClient().GetAsync("/", ct);

        AssertHeaders(response);
    }

    [Fact]
    public async Task AnErrorPage_CarriesTheHeaders()
    {
        // UseExceptionHandler clears the response headers before it re-executes; the headers are
        // written when the response starts, so the error answer carries them too.
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync(app =>
        {
            app.UseExceptionHandler(error => error.Run(context => context.Response.WriteAsync("error")));
            app.MapGet("/", (Func<string>)(() => throw new InvalidOperationException("boom")));
        }, ct);

        var response = await app.GetTestClient().GetAsync("/", ct);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        AssertHeaders(response);
    }

    [Fact]
    public async Task AFrameOptionsValueSetByTheApp_IsReplacedWithDeny()
    {
        // Antiforgery writes SAMEORIGIN on every page with a form. Nothing in Qertum frames its own
        // pages, so DENY is the one value; two values would leave the browser to pick.
        var ct = TestContext.Current.CancellationToken;
        await using var app = await StartAsync(app => app.MapGet("/", (HttpContext context) =>
        {
            context.Response.Headers.XFrameOptions = "SAMEORIGIN";
            return "form";
        }), ct);

        var response = await app.GetTestClient().GetAsync("/", ct);

        Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
    }

    [Fact]
    public async Task ARealHost_SendsTheHeaders()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = new EstTestFactory();

        var response = await factory.CreateClient().GetAsync("/.well-known/est/cacerts", ct);

        AssertHeaders(response);
    }

    [Theory]
    [MemberData(nameof(HostNames))]
    public void EveryHost_AddsTheHeadersBeforeAnyOtherMiddleware(string host)
    {
        // First, so every later middleware's answer (rate-limit 429, auth 401, status pages) has them.
        var source = File.ReadAllText(Path.Combine(FindRepoRoot(), host, "Program.cs"));
        var firstUse = Regex.Match(source, @"\bapp\.Use[A-Za-z]*\(");

        Assert.True(firstUse.Success, $"{host}/Program.cs adds no middleware.");
        Assert.StartsWith("app.UseQertumSecurityHeaders(", source[firstUse.Index..], StringComparison.Ordinal);
    }

    public static TheoryData<string> HostNames() => new(Hosts);

    [Fact]
    public async Task AHostsOwnPolicy_ReplacesTheDefault()
    {
        var ct = TestContext.Current.CancellationToken;
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        await using var app = builder.Build();
        app.UseQertumSecurityHeaders(SecurityHeaders.IdentityPolicy);
        app.MapGet("/", () => "ok");
        await app.StartAsync(ct);

        var response = await app.GetTestClient().GetAsync("/", ct);

        Assert.Equal(SecurityHeaders.IdentityPolicy, Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
        Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
    }

    [Fact]
    public void WebPolicy_AllowsScriptsFromItselfOnly_AndSignOutToTheIdentityOrigin()
    {
        var policy = SecurityHeaders.WebPolicy("https://id.example.com:8443/some/path");

        Assert.Contains("script-src 'self';", policy, StringComparison.Ordinal);
        Assert.DoesNotContain("unsafe-eval", policy, StringComparison.Ordinal);
        Assert.Contains("form-action 'self' https://id.example.com:8443;", policy, StringComparison.Ordinal);
        Assert.Contains("frame-ancestors 'none'", policy, StringComparison.Ordinal);
        Assert.Contains("form-action 'self';", SecurityHeaders.WebPolicy(null), StringComparison.Ordinal);
    }

    [Fact]
    public void NoPage_CarriesInlineScriptOrAnInlineEventHandler()
    {
        // The web and identity policies allow script from the host itself only (plus OpenIddict's one hashed
        // form_post script). An inline <script> or onclick="..." would be refused by the browser, silently.
        var root = FindRepoRoot();
        var offenders = new List<string>();
        foreach (var file in UiSources(root, "*.razor", "*.cshtml", "*.html")
                     .Concat(Directory.EnumerateFiles(Path.Combine(root, "Qertum.IdentityService"), "*.cs", SearchOption.AllDirectories)
                         .Where(f => !IsBuildOutput(f))))
        {
            var text = File.ReadAllText(file);
            if (Regex.IsMatch(text, @"<script(?![^>]*\bsrc=)[^>]*>", RegexOptions.IgnoreCase)
                // Case-sensitive: HTML handlers are lower case; OnConfirm="..." is a Blazor component parameter.
                || Regex.IsMatch(text, @"\son[a-z]+\s*=\s*[""']"))
                offenders.Add(Path.GetRelativePath(root, file));
        }

        Assert.Empty(offenders);
    }

    [Fact]
    public void NoPage_LoadsAScriptStyleOrFontFromAnotherOrigin()
    {
        // The policies name no other origin, and a CA's admin UI must also work offline: icons and fonts are
        // served from Qertum.DesignSystem. Vendored libraries under wwwroot/lib are not scanned.
        var root = FindRepoRoot();
        var offenders = UiSources(root, "*.razor", "*.cshtml", "*.html", "*.css")
            .Where(f => Regex.IsMatch(File.ReadAllText(f),
                @"(src|href)\s*=\s*[""']https?://|@import\s+url\(\s*['""]?https?://|url\(\s*['""]?https?://", RegexOptions.IgnoreCase))
            .Select(f => Path.GetRelativePath(root, f))
            .ToList();

        Assert.Empty(offenders);
    }

    private static IEnumerable<string> UiSources(string root, params string[] patterns) =>
        new[] { "Qertum.Web", "Qertum.IdentityService", "Qertum.DesignSystem" }
            .SelectMany(project => patterns.SelectMany(pattern =>
                Directory.EnumerateFiles(Path.Combine(root, project), pattern, SearchOption.AllDirectories)))
            .Where(f => !IsBuildOutput(f) && !f.Contains($"{Path.DirectorySeparatorChar}wwwroot{Path.DirectorySeparatorChar}lib{Path.DirectorySeparatorChar}"));

    private static bool IsBuildOutput(string path) =>
        path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
        || path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}");

    private static void AssertHeaders(HttpResponseMessage response)
    {
        Assert.Equal("nosniff", Assert.Single(response.Headers.GetValues("X-Content-Type-Options")));
        Assert.Equal("no-referrer", Assert.Single(response.Headers.GetValues("Referrer-Policy")));
        Assert.Equal("DENY", Assert.Single(response.Headers.GetValues("X-Frame-Options")));
        Assert.Equal("frame-ancestors 'none'", Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
    }

    private static async Task<WebApplication> StartAsync(Action<WebApplication> configure, CancellationToken ct)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        var app = builder.Build();
        app.UseQertumSecurityHeaders();
        configure(app);
        await app.StartAsync(ct);
        return app;
    }

    private static string FindRepoRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Qertum.sln")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new InvalidOperationException("Qertum.sln not found.");
    }
}
