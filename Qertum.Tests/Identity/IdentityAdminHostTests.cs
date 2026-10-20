using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;
using static Qertum.Tests.Identity.IdentityHostTestKit;

namespace Qertum.Tests.Identity;

public sealed class IdentityAdminHostTests : IDisposable
{
    private const string Password = "Admin-Host-Test-1!";
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
        var dir = Path.Combine(Path.GetTempPath(), $"idp-admin-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        _dataPaths.Add(dir);
        return CreateFactory(dir, clock);
    }

    private static Task<StoredUser> CreateUserAsync(
        WebApplicationFactory<IdentityServiceProgram> factory, string username, string[] roles, CancellationToken ct, bool mustChange = false) =>
        factory.Services.GetRequiredService<JsonUserStore>()
            .CreateUserAsync(username, $"{username}@t.local", username, Password, [.. roles], mustChange, ct);

    [Theory]
    [InlineData("/Admin/Users")]
    [InlineData("/Admin/Confirm")]
    public async Task NonAdmin_IsForbidden_OnAdminPages(string url)
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "viewer1", ["viewer"], ct);
        await LoginAsync(client, "viewer1", Password, ct);

        using var response = await client.GetAsync(url, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task NonAdmin_PostToConfirm_IsForbidden()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "viewer2", ["viewer"], ct);
        await LoginAsync(client, "viewer2", Password, ct);

        using var response = await PostFormAsync(client, "/Account", "/Admin/Confirm", [KeyValuePair.Create("Password", Password)], ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Anonymous_IsSentToLogin()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);

        using var response = await client.GetAsync("/Admin/Users", ct);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Contains("/login", response.Headers.Location!.OriginalString, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Admin_WithoutStepUp_IsSentToConfirm_WithReturnUrl()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "boss", ["admin"], ct);
        await LoginAsync(client, "boss", Password, ct);

        using var response = await client.GetAsync("/Admin/Users?q=bo", ct);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/Admin/Confirm?returnUrl=%2FAdmin%2FUsers%3Fq%3Dbo", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task StepUp_LastsFiveMinutes_ThenAsksAgain()
    {
        var ct = TestContext.Current.CancellationToken;
        var clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        using var factory = Factory(clock);
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "boss", ["admin"], ct);
        await LoginAsync(client, "boss", Password, ct);

        await ConfirmStepUpAsync(client, Password, ct);
        using (var fresh = await client.GetAsync("/Admin/Users", ct))
        {
            Assert.Equal(HttpStatusCode.OK, fresh.StatusCode);
        }

        clock.Advance(TimeSpan.FromMinutes(4));
        using (var stillFresh = await client.GetAsync("/Admin/Users", ct))
        {
            Assert.Equal(HttpStatusCode.OK, stillFresh.StatusCode);
        }

        clock.Advance(TimeSpan.FromMinutes(2));
        using var expired = await client.GetAsync("/Admin/Users", ct);
        Assert.Equal(HttpStatusCode.Found, expired.StatusCode);
        Assert.StartsWith("/Admin/Confirm", expired.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task Confirm_ReturnUrl_MustBeLocal()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "boss", ["admin"], ct);
        await LoginAsync(client, "boss", Password, ct);

        using var response = await PostFormAsync(client, "/Admin/Confirm", "/Admin/Confirm",
            [KeyValuePair.Create("Password", Password), KeyValuePair.Create("ReturnUrl", "https://evil.example/")], ct);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.Equal("/Admin/Users", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task WrongStepUpPassword_IsRateLimited_AndAudited()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "boss", ["admin"], ct);
        await LoginAsync(client, "boss", Password, ct);

        for (var i = 0; i < 5; i++)
        {
            using var wrong = await PostFormAsync(client, "/Admin/Confirm", "/Admin/Confirm", [KeyValuePair.Create("Password", "nope")], ct);
            Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
            Assert.Contains("Password is incorrect.", await wrong.Content.ReadAsStringAsync(ct));
        }

        using var limited = await PostFormAsync(client, "/Admin/Confirm", "/Admin/Confirm", [KeyValuePair.Create("Password", Password)], ct);
        Assert.Equal(HttpStatusCode.OK, limited.StatusCode);
        Assert.Contains("Too many failed attempts", await limited.Content.ReadAsStringAsync(ct));

        var entries = await factory.Services.GetRequiredService<IdentityAuditLogReader>().ReadAsync(0, 50, ct);
        Assert.Equal(5, entries.Count(e => e.Action == IdentityAuditActions.StepUpFailed && e.PerformedBy == "boss"));
    }

    [Fact]
    public async Task FlaggedAdmin_IsSentToChangePassword_BeforeStepUp()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "newboss", ["admin"], ct, mustChange: true);
        await LoginAsync(client, "newboss", Password, ct);

        using var response = await client.GetAsync("/Admin/Users", ct);

        Assert.Equal(HttpStatusCode.Found, response.StatusCode);
        Assert.StartsWith("/Account/ChangePassword", response.Headers.Location!.OriginalString);
    }

    [Fact]
    public async Task OldUsersPage_IsGone()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "boss", ["admin"], ct);
        await LoginAsync(client, "boss", Password, ct);

        using var response = await client.GetAsync("/Account/Users", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task UsersList_FiltersByQuery()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = Factory();
        using var client = CreateClient(factory);
        await CreateUserAsync(factory, "boss", ["admin"], ct);
        await CreateUserAsync(factory, "alice", ["viewer"], ct);
        await CreateUserAsync(factory, "robert", ["viewer"], ct);
        await LoginAsync(client, "boss", Password, ct);
        await ConfirmStepUpAsync(client, Password, ct);

        using var response = await client.GetAsync("/Admin/Users?q=ALI", ct);
        var html = await response.Content.ReadAsStringAsync(ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("alice@t.local", html);
        Assert.DoesNotContain("robert@t.local", html);
    }
}
