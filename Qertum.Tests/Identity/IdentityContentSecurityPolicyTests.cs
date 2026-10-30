using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Hosting;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

/// <summary>
/// The identity service's Content-Security-Policy against the pages it really sends. The one inline script it
/// may run is OpenIddict's form_post auto-submit; if an upgrade changes that script, the sign-in would stop at a
/// "click here" button, and this test fails first.
/// </summary>
public sealed partial class IdentityContentSecurityPolicyTests : IDisposable
{
    private const string Password = "Csp-Test-Password-1!";
    private readonly string _dataPath = Path.Combine(Path.GetTempPath(), "qertum-csp-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dataPath, recursive: true); } catch { /* best effort */ }
    }

    [Fact]
    public async Task FormPostResponse_RunsOnlyTheScriptThePolicyAllows()
    {
        var ct = TestContext.Current.CancellationToken;
        Directory.CreateDirectory(_dataPath);
        using var factory = IdentityHostTestKit.CreateFactory(_dataPath);
        using var client = IdentityHostTestKit.CreateClient(factory);
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("csp-user", "c@t.local", "C", Password, ["viewer"], cancellationToken: ct);
        await IdentityHostTestKit.LoginAsync(client, "csp-user", Password, ct);

        var response = await client.GetAsync("/connect/authorize" +
            "?client_id=qertum-web&response_type=code&response_mode=form_post" +
            "&redirect_uri=" + Uri.EscapeDataString("https://localhost:7077/signin-oidc") +
            "&scope=openid&state=s&nonce=n" +
            "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", ct);
        var html = await response.Content.ReadAsStringAsync(ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var scripts = InlineScript().Matches(html).Select(m => m.Groups[1].Value).ToList();
        var script = Assert.Single(scripts);
        var hash = "sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(script)));
        Assert.Equal(SecurityHeaders.OpenIddictFormPostScriptHash, hash);
        Assert.Equal(SecurityHeaders.IdentityPolicy, Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
    }

    [Fact]
    public async Task LoginPage_CarriesThePolicyAndNoInlineScript()
    {
        var ct = TestContext.Current.CancellationToken;
        Directory.CreateDirectory(_dataPath);
        using var factory = IdentityHostTestKit.CreateFactory(_dataPath);
        using var client = IdentityHostTestKit.CreateClient(factory);

        var response = await client.GetAsync("/login", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(SecurityHeaders.IdentityPolicy, Assert.Single(response.Headers.GetValues("Content-Security-Policy")));
        Assert.Empty(InlineScript().Matches(await response.Content.ReadAsStringAsync(ct)));
    }

    [GeneratedRegex(@"<script>(.*?)</script>", RegexOptions.Singleline)]
    private static partial Regex InlineScript();
}
