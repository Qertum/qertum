using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using Qertum.IdentityService.Pages;
using Qertum.IdentityService.Services;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

/// <summary>
/// Login attempts share a per-username budget and answer identically for known and unknown users.
/// </summary>
public sealed class LoginRateLimitTests
{
    private const string GoodPassword = "Correct-Login-Pass-1!";

    private sealed class RecordingAudit : IIdentityAuditLog
    {
        public List<(string Action, string PerformedBy, string? ResourceName, string? Detail)> Entries { get; } = [];

        public void Write(string action, string performedBy, Guid? resourceId = null,
            string? resourceName = null, string? detail = null)
            => Entries.Add((action, performedBy, resourceName, detail));
    }

    private sealed class NoopAuthenticationService : IAuthenticationService
    {
        public Task SignInAsync(HttpContext context, string? scheme, ClaimsPrincipal principal, AuthenticationProperties? properties)
            => Task.CompletedTask;

        public Task<AuthenticateResult> AuthenticateAsync(HttpContext context, string? scheme) => throw new NotSupportedException();
        public Task ChallengeAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task ForbidAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
        public Task SignOutAsync(HttpContext context, string? scheme, AuthenticationProperties? properties) => throw new NotSupportedException();
    }

    private static async Task<JsonUserStore> CreateStoreAsync(CancellationToken ct)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"login-limit-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var users = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        await users.CreateUserAsync("bob", "bob@example.test", "Bob", GoodPassword, [], false, ct);
        return users;
    }

    private static LoginModel CreateModel(JsonUserStore users, IPasswordAttemptLimiter limiter, RecordingAudit audit)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService, NoopAuthenticationService>();

        return new LoginModel(users, limiter, audit)
        {
            PageContext = new PageContext(new ActionContext(
                new DefaultHttpContext { RequestServices = services.BuildServiceProvider() },
                new RouteData(), new ActionDescriptor(), new ModelStateDictionary()))
        };
    }

    [Fact]
    public async Task SixthWrongPassword_IsThrottledWithTheSameMessage()
    {
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 9, 15, 9, 0, 0, TimeSpan.Zero));
        var audit = new RecordingAudit();
        var limiter = new PasswordAttemptLimiter(cache, time);

        for (var attempt = 0; attempt < LoginModel.MaxAttempts; attempt++)
        {
            var model = CreateModel(users, limiter, audit);
            model.Input = new LoginModel.InputModel { Username = "bob", Password = "wrong" };
            await model.OnPostAsync(ct);
            Assert.Equal("Invalid username or password.", model.ErrorMessage);
        }

        var throttled = CreateModel(users, limiter, audit);
        throttled.Input = new LoginModel.InputModel { Username = "bob", Password = GoodPassword };
        await throttled.OnPostAsync(ct);

        Assert.Equal("Invalid username or password.", throttled.ErrorMessage);
        Assert.Equal([("LoginThrottled", "bob")], audit.Entries.Select(e => (e.Action, e.PerformedBy)));
        Assert.DoesNotContain(audit.Entries, e => (e.ResourceName ?? "") .Contains(GoodPassword) || (e.Detail ?? "").Contains(GoodPassword));
    }

    [Fact]
    public async Task WindowExpires_AndSuccessClearsTheCounter()
    {
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        var cache = new MemoryCache(new MemoryCacheOptions());
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 9, 15, 9, 0, 0, TimeSpan.Zero));
        var audit = new RecordingAudit();
        var limiter = new PasswordAttemptLimiter(cache, time);

        for (var attempt = 0; attempt < LoginModel.MaxAttempts; attempt++)
        {
            var model = CreateModel(users, limiter, audit);
            model.Input = new LoginModel.InputModel { Username = "bob", Password = "wrong" };
            await model.OnPostAsync(ct);
        }

        time.Advance(LoginModel.Window + TimeSpan.FromMinutes(1));

        var afterWindow = CreateModel(users, limiter, audit);
        afterWindow.Input = new LoginModel.InputModel { Username = "bob", Password = GoodPassword };
        var result = await afterWindow.OnPostAsync(ct);

        Assert.Null(afterWindow.ErrorMessage);
        Assert.IsType<RedirectResult>(result);
    }

    [Fact]
    public async Task ConcurrentWrongPasswordsUseOneSharedAttemptBudget()
    {
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var time = new FakeTimeProvider(new DateTimeOffset(2026, 9, 15, 9, 0, 0, TimeSpan.Zero));
        var audit = new RecordingAudit();
        var limiter = new PasswordAttemptLimiter(cache, time);

        var attempts = Enumerable.Range(0, 16).Select(_ =>
        {
            var model = CreateModel(users, limiter, audit);
            model.Input = new LoginModel.InputModel { Username = "bob", Password = "wrong" };
            return model.OnPostAsync(ct);
        });
        await Task.WhenAll(attempts);

        var next = CreateModel(users, limiter, audit);
        next.Input = new LoginModel.InputModel { Username = "bob", Password = GoodPassword };
        await next.OnPostAsync(ct);

        Assert.Equal("Invalid username or password.", next.ErrorMessage);
        Assert.NotEmpty(audit.Entries);
    }

    [Fact]
    public async Task UnknownUsernameUsesTheSameErrorAndAttemptBudget()
    {
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new PasswordAttemptLimiter(cache, TimeProvider.System);
        var audit = new RecordingAudit();

        for (var attempt = 0; attempt <= LoginModel.MaxAttempts; attempt++)
        {
            var model = CreateModel(users, limiter, audit);
            model.Input = new LoginModel.InputModel { Username = "unknown", Password = "wrong" };
            await model.OnPostAsync(ct);
            Assert.Equal("Invalid username or password.", model.ErrorMessage);
        }

        Assert.Single(audit.Entries, entry => entry.Action == IdentityAuditActions.LoginThrottled);
    }
}
