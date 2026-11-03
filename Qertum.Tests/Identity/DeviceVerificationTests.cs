using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

/// <summary>
/// The device-flow confirmation page (<c>/connect/verify</c>) grants a device the signed-in user's
/// tokens. Its approval used to be any authenticated POST carrying a user code, so a page on a
/// same-site origin could approve an attacker's device for the victim; and the page put the
/// username and user code into its HTML unencoded.
/// </summary>
public sealed class DeviceVerificationTests : IDisposable
{
    private const string Password = "Device-Verify-Test-1!";
    private readonly string _dataPath = Path.Combine(Path.GetTempPath(), "qertum-device-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dataPath, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<JsonElement> StartDeviceFlowAsync(HttpClient client)
    {
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = "qca",
                ["scope"] = "openid profile roles offline_access qertum-api"
            });
        using var authorization = await client.PostAsync("/connect/device_authorization",
            form, Ct);
        authorization.EnsureSuccessStatusCode();
        return (await authorization.Content.ReadFromJsonAsync<JsonDocument>(Ct))!.RootElement;
    }

    [Fact]
    public async Task AnApprovalWithoutTheConfirmationPagesToken_IsRefusedAndGrantsNothing()
    {
        await using var factory = IdentityHostTestKit.CreateFactory(_dataPath);
        using var client = IdentityHostTestKit.CreateClient(factory);
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("victim", "v@t.local", "V", Password, ["admin"], cancellationToken: Ct);
        var codes = await StartDeviceFlowAsync(client);
        await IdentityHostTestKit.LoginAsync(client, "victim", Password, Ct);

        using var form2 = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["user_code"] = codes.GetProperty("user_code").GetString()!
        });
        using var verify = await client.PostAsync("/connect/verify", form2, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, verify.StatusCode);
        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
            ["client_id"] = "qca",
            ["device_code"] = codes.GetProperty("device_code").GetString()!
        });
        using var token = await client.PostAsync("/connect/token", form, Ct);
        Assert.Contains("authorization_pending", await token.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task TheConfirmationPageAndItsTokenComplete_TheDeviceFlow()
    {
        await using var factory = IdentityHostTestKit.CreateFactory(_dataPath);
        using var client = IdentityHostTestKit.CreateClient(factory);
        await factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync("owner", "o@t.local", "O", Password, ["viewer"], cancellationToken: Ct);

        var (accessToken, _) = await IdentityHostTestKit.ObtainTokensViaDeviceFlowAsync(client, "owner", Password, Ct);

        Assert.False(string.IsNullOrEmpty(accessToken));
    }

    [Fact]
    public void TheConfirmationPageEncodesTheUsernameAndTheUserCode()
    {
        var html = Qertum.IdentityService.Controllers.AuthorizationController.DeviceConfirmationHtml(
            "<img src=x onerror=alert(1)>", "\"><b>code</b>", "__RequestVerificationToken", "tok\"en");

        Assert.DoesNotContain("<img", html);
        Assert.DoesNotContain("<b>code", html);
        Assert.Contains("&lt;img", html);
        Assert.DoesNotContain("value=\"tok\"en\"", html);
    }
}
