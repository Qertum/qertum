using System.Net;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

/// <summary>
/// <c>/connect/logout</c> ended the identity session on any GET, so another site could sign a user out with a link or an
/// image (logout CSRF, AI Scan #348 on 1.0.0-rc4.2). It now signs out at once only with a validated id_token_hint for the
/// signed-in user (what the web app sends) or the confirmation form's own POST; anything else shows the form.
/// </summary>
public sealed partial class LogoutConfirmationTests : IDisposable
{
    private const string Password = "Logout-Confirm-Test-1!";
    private readonly string _dataPath = Path.Combine(Path.GetTempPath(), "qertum-logout-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dataPath, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<bool> IsSignedInAsync(HttpClient client)
    {
        // Signed in: the code-entry redirect. Signed out: the login challenge.
        using var response = await client.GetAsync("/connect/verify", Ct);
        return response.Headers.Location?.OriginalString.Contains("/device", StringComparison.Ordinal) == true;
    }

    private async Task<(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<IdentityServiceProgram> Factory, HttpClient Client)> SignedInAsync(params string[] users)
    {
        var factory = IdentityHostTestKit.CreateFactory(_dataPath);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        foreach (var user in users)
            await store.CreateUserAsync(user, $"{user}@t.local", user, Password, ["viewer"], cancellationToken: Ct);
        var client = IdentityHostTestKit.CreateClient(factory);
        return (factory, client);
    }

    [Fact]
    public async Task ABareGet_ShowsTheConfirmation_AndKeepsTheSession()
    {
        var (factory, client) = await SignedInAsync("alice");
        await using var _ = factory;
        using var __ = client;
        await IdentityHostTestKit.LoginAsync(client, "alice", Password, Ct);

        using var response = await client.GetAsync("/connect/logout", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Sign out of Qertum Identity?", await response.Content.ReadAsStringAsync(Ct));
        Assert.True(await IsSignedInAsync(client));
    }

    [Fact]
    public async Task TheConfirmationFormsPost_SignsOut()
    {
        var (factory, client) = await SignedInAsync("alice");
        await using var _ = factory;
        using var __ = client;
        await IdentityHostTestKit.LoginAsync(client, "alice", Password, Ct);

        using var response = await IdentityHostTestKit.PostFormAsync(client, "/connect/logout", "/connect/logout",
            [KeyValuePair.Create("confirm", "true")], Ct);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.False(await IsSignedInAsync(client));
    }

    [Fact]
    public async Task AConfirmPostWithoutTheToken_DoesNotSignOut()
    {
        var (factory, client) = await SignedInAsync("alice");
        await using var _ = factory;
        using var __ = client;
        await IdentityHostTestKit.LoginAsync(client, "alice", Password, Ct);

        using var form = new FormUrlEncodedContent([KeyValuePair.Create("confirm", "true")]);
        using var response = await client.PostAsync("/connect/logout", form, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(await IsSignedInAsync(client));
    }

    [Fact]
    public async Task TheUsersOwnIdTokenHint_SignsOutAtOnce()
    {
        var (factory, client) = await SignedInAsync("alice");
        await using var _ = factory;
        using var __ = client;
        var tokens = await IdentityHostTestKit.ObtainTokenResponseViaDeviceFlowAsync(client, "alice", Password, Ct);

        using var response = await client.GetAsync(
            "/connect/logout?id_token_hint=" + Uri.EscapeDataString(tokens.GetProperty("id_token").GetString()!), Ct);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.False(await IsSignedInAsync(client));
    }

    [Fact]
    public async Task AnotherUsersIdTokenHint_ShowsTheConfirmation()
    {
        var (factory, client) = await SignedInAsync("alice", "mallory");
        await using var _ = factory;
        using var __ = client;
        using var attacker = IdentityHostTestKit.CreateClient(factory);
        var mallorys = await IdentityHostTestKit.ObtainTokenResponseViaDeviceFlowAsync(attacker, "mallory", Password, Ct);
        await IdentityHostTestKit.LoginAsync(client, "alice", Password, Ct);

        using var response = await client.GetAsync(
            "/connect/logout?id_token_hint=" + Uri.EscapeDataString(mallorys.GetProperty("id_token").GetString()!), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var html = await response.Content.ReadAsStringAsync(Ct);
        Assert.DoesNotMatch(IdTokenHintField(), html);
        Assert.True(await IsSignedInAsync(client));
    }

    [Fact]
    public async Task NotSignedIn_IsRedirectedWithoutAPage()
    {
        var (factory, client) = await SignedInAsync();
        await using var _ = factory;
        using var __ = client;

        using var response = await client.GetAsync("/connect/logout", Ct);

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
    }

    [GeneratedRegex("name=\"id_token_hint\"")]
    private static partial Regex IdTokenHintField();
}
