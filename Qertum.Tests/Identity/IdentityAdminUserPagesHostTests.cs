using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using OpenIddict.Abstractions;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;
using static Qertum.Tests.Identity.IdentityHostTestKit;

namespace Qertum.Tests.Identity;

public sealed class IdentityAdminUserPagesHostTests : IDisposable
{
    private const string Password = "Admin-Pages-Test-1!";
    private readonly List<string> _dataPaths = [];

    public void Dispose()
    {
        foreach (var dir in _dataPaths)
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    private WebApplicationFactory<IdentityServiceProgram> Factory(TimeProvider? clock = null)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-admin-pages-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _dataPaths.Add(dir);
        return CreateFactory(dir, clock);
    }

    private static Task<StoredUser> CreateUserAsync(
        WebApplicationFactory<IdentityServiceProgram> factory, string username, string[] roles, CancellationToken ct) =>
        factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync(username, $"{username}@t.local", username, Password, [.. roles], false, ct);

    private static async Task<HttpClient> SignedInAdminAsync(WebApplicationFactory<IdentityServiceProgram> factory, CancellationToken ct)
    {
        await CreateUserAsync(factory, "boss", ["admin"], ct);
        await factory.Services.GetRequiredService<JsonRoleStore>().CreateAsync("viewer", "Can view certificates.", ct);
        var client = CreateClient(factory);
        await LoginAsync(client, "boss", Password, ct);
        await ConfirmStepUpAsync(client, Password, ct);
        return client;
    }

    [Fact]
    public async Task CreateUser_ShowsOneTimePasswordOnce_NoStore_AndForcesChangeAtFirstLogin()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);

        using var created = await PostFormAsync(admin, "/Admin/Users/New", "/Admin/Users/New",
        [
            KeyValuePair.Create("Input.Username", "newbie"),
            KeyValuePair.Create("Input.DisplayName", "New Bie"),
            KeyValuePair.Create("Input.Email", "newbie@t.local"),
            KeyValuePair.Create("Input.Roles", "viewer")
        ], ct);

        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        Assert.True(created.Headers.CacheControl?.NoStore, "The one-time password response must not be cached.");
        var match = OneTimePasswordPattern().Match(await created.Content.ReadAsStringAsync(ct));
        Assert.True(match.Success, "No one-time password was shown.");
        var oneTimePassword = match.Groups[1].Value.Trim();

        using (var again = await admin.GetAsync("/Admin/Users/New", ct))
        {
            Assert.DoesNotContain(oneTimePassword, await again.Content.ReadAsStringAsync(ct));
        }

        using var newbie = CreateClient(factory);
        using var login = await PostFormAsync(newbie, "/login", "/login",
            [KeyValuePair.Create("Input.Username", "newbie"), KeyValuePair.Create("Input.Password", oneTimePassword)], ct);
        Assert.Equal(HttpStatusCode.Found, login.StatusCode);
        Assert.StartsWith("/Account/ChangePassword?forced=true", login.Headers.Location!.OriginalString);

        var auditText = string.Concat(Directory.GetFiles(Path.Combine(_dataPaths[^1], "audit-logs")).Select(File.ReadAllText));
        Assert.Contains("UserCreated", auditText);
        Assert.DoesNotContain(oneTimePassword, auditText);
    }

    [Fact]
    public async Task NonAdmin_PostToNewUser_IsForbidden_AndCreatesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        await CreateUserAsync(factory, "viewer1", ["viewer"], ct);
        using var client = CreateClient(factory);
        await LoginAsync(client, "viewer1", Password, ct);

        using var response = await PostFormAsync(client, "/Account", "/Admin/Users/New",
            [KeyValuePair.Create("Input.Username", "sneaky"), KeyValuePair.Create("Input.Email", "s@t.local")], ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(await factory.Services.GetRequiredService<JsonUserStore>().FindByUsernameAsync("sneaky", ct));
    }

    [Fact]
    public async Task PostAfterStepUpExpired_RedirectsWithExpired_AndChangesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var factory = Factory(clock);
        using var admin = await SignedInAdminAsync(factory, ct);
        var target = await CreateUserAsync(factory, "target", ["viewer"], ct);
        var detailUrl = $"/Admin/Users/{target.Id}";

        var token = await GetAntiforgeryTokenAsync(admin, detailUrl, ct);
        clock.Advance(TimeSpan.FromMinutes(6));
        using var response = await admin.PostAsync($"{detailUrl}?handler=Disable",
            new FormUrlEncodedContent([KeyValuePair.Create("__RequestVerificationToken", token)]), ct);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal($"/Admin/Confirm?returnUrl={Uri.EscapeDataString(detailUrl)}&expired=true", response.Headers.Location!.OriginalString);
        Assert.False((await factory.Services.GetRequiredService<JsonUserStore>().FindByIdAsync(target.Id, ct))!.IsDisabled);
    }

    [Fact]
    public async Task ResetPassword_ShowsOneTimePassword_AndEndsTargetsSessionAndRefreshToken()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);
        var target = await CreateUserAsync(factory, "target", ["viewer"], ct);
        using var targetClient = CreateClient(factory);
        var (_, refreshToken) = await ObtainTokensViaDeviceFlowAsync(targetClient, "target", Password, ct);

        var detailUrl = $"/Admin/Users/{target.Id}";
        using var reset = await PostFormAsync(admin, detailUrl, $"{detailUrl}?handler=ResetPassword", [], ct);

        Assert.Equal(HttpStatusCode.OK, reset.StatusCode);
        Assert.True(reset.Headers.CacheControl?.NoStore);
        Assert.Matches(OneTimePasswordPattern(), await reset.Content.ReadAsStringAsync(ct));

        using var session = await targetClient.GetAsync("/Account", ct);
        Assert.Equal(HttpStatusCode.Found, session.StatusCode);
        Assert.Contains("/login", session.Headers.Location!.OriginalString, StringComparison.OrdinalIgnoreCase);

        using var refresh = await RefreshAsync(targetClient, refreshToken, ct);
        await AssertInvalidGrantAsync(refresh, ct);
    }

    [Fact]
    public async Task DeleteUser_RevokesStoredGrants_AndEndsSession()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);
        var target = await CreateUserAsync(factory, "leaving", ["viewer"], ct);
        using var targetClient = CreateClient(factory);
        var (_, refreshToken) = await ObtainTokensViaDeviceFlowAsync(targetClient, "leaving", Password, ct);

        var detailUrl = $"/Admin/Users/{target.Id}";
        using var delete = await PostFormAsync(admin, detailUrl, $"{detailUrl}?handler=Delete", [], ct);

        Assert.Equal(HttpStatusCode.Found, delete.StatusCode);
        Assert.Equal("/Admin/Users", delete.Headers.Location!.OriginalString);
        Assert.Null(await factory.Services.GetRequiredService<JsonUserStore>().FindByIdAsync(target.Id, ct));

        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var tokens = scope.ServiceProvider.GetRequiredService<IOpenIddictTokenManager>();
            var statuses = new List<string?>();
            await foreach (var token in tokens.FindBySubjectAsync(target.Id.ToString(), ct))
            {
                statuses.Add(await tokens.GetStatusAsync(token, ct));
            }

            Assert.NotEmpty(statuses);
            Assert.DoesNotContain(OpenIddictConstants.Statuses.Valid, statuses);
        }

        using var session = await targetClient.GetAsync("/Account", ct);
        Assert.Equal(HttpStatusCode.Found, session.StatusCode);
        using var refresh = await RefreshAsync(targetClient, refreshToken, ct);
        await AssertInvalidGrantAsync(refresh, ct);
    }

    [Fact]
    public async Task RemovingOwnAdminRole_ShowsFixedMessage_AndKeepsTheRole()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);
        var store = factory.Services.GetRequiredService<JsonUserStore>();
        var boss = (await store.FindByUsernameAsync("boss", ct))!;

        var detailUrl = $"/Admin/Users/{boss.Id}";
        using var response = await PostFormAsync(admin, detailUrl, $"{detailUrl}?handler=Roles",
            [KeyValuePair.Create("Roles", "viewer")], ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("You cannot remove your own admin role.", await response.Content.ReadAsStringAsync(ct));
        Assert.Contains("admin", (await store.FindByIdAsync(boss.Id, ct))!.Roles);
    }

    [Fact]
    public async Task PostedRoleNotInCatalog_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);
        var target = await CreateUserAsync(factory, "target", ["viewer"], ct);

        var detailUrl = $"/Admin/Users/{target.Id}";
        using var response = await PostFormAsync(admin, detailUrl, $"{detailUrl}?handler=Roles",
            [KeyValuePair.Create("Roles", "superuser")], ct);

        Assert.Contains("One or more selected roles are not in the role catalog.", await response.Content.ReadAsStringAsync(ct));
        Assert.Equal(["viewer"], (await factory.Services.GetRequiredService<JsonUserStore>().FindByIdAsync(target.Id, ct))!.Roles);
    }

    [Fact]
    public async Task DetailPage_WarnsAboutHeldRolesMissingFromCatalog()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var admin = await SignedInAdminAsync(factory, ct);
        var target = await CreateUserAsync(factory, "legacyuser", ["legacy"], ct);

        using var response = await admin.GetAsync($"/Admin/Users/{target.Id}", ct);

        Assert.Contains("Not in the role catalog: legacy", await response.Content.ReadAsStringAsync(ct));
    }
}
