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
/// Login attempts share a budget per username and client address, under a looser per-username ceiling and a
/// per-address ceiling across usernames, and answer identically for known and unknown users.
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

    private static LoginModel CreateModel(JsonUserStore users, IPasswordAttemptLimiter limiter, RecordingAudit audit,
        string? clientAddress = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IAuthenticationService, NoopAuthenticationService>();
        var http = new DefaultHttpContext { RequestServices = services.BuildServiceProvider() };
        if (clientAddress is not null) http.Connection.RemoteIpAddress = System.Net.IPAddress.Parse(clientAddress);

        return new LoginModel(users, limiter, audit)
        {
            PageContext = new PageContext(new ActionContext(
                http, new RouteData(), new ActionDescriptor(), new ModelStateDictionary()))
        };
    }

    private static async Task<LoginModel> AttemptAsync(JsonUserStore users, IPasswordAttemptLimiter limiter, RecordingAudit audit,
        string address, string password, CancellationToken ct)
    {
        var model = CreateModel(users, limiter, audit, address);
        model.Input = new LoginModel.InputModel { Username = "bob", Password = password };
        await model.OnPostAsync(ct);
        return model;
    }

    [Fact]
    public async Task WrongPasswordsFromOneAddress_DoNotLockTheAccountForAnotherAddress()
    {
        // The budget was per username only, so anyone could lock admin out by typing wrong passwords for it.
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new PasswordAttemptLimiter(cache, new FakeTimeProvider(new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero)));
        var audit = new RecordingAudit();

        for (var attempt = 0; attempt < LoginModel.MaxAttempts; attempt++)
            await AttemptAsync(users, limiter, audit, "203.0.113.66", "wrong", ct);
        var attacker = await AttemptAsync(users, limiter, audit, "203.0.113.66", GoodPassword, ct);
        var owner = await AttemptAsync(users, limiter, audit, "198.51.100.7", GoodPassword, ct);

        Assert.Equal("Invalid username or password.", attacker.ErrorMessage);
        Assert.Null(owner.ErrorMessage);
    }

    [Fact]
    public async Task AGuessSpreadAcrossAddresses_StillMeetsThePerAccountCeiling()
    {
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new PasswordAttemptLimiter(cache, new FakeTimeProvider(new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero)));
        var audit = new RecordingAudit();

        for (var attempt = 0; attempt < LoginModel.AccountCeiling; attempt++)
            await AttemptAsync(users, limiter, audit, $"10.0.{attempt / 250}.{attempt % 250 + 1}", "wrong", ct);
        var fresh = await AttemptAsync(users, limiter, audit, "198.51.100.7", GoodPassword, ct);

        Assert.Equal("Invalid username or password.", fresh.ErrorMessage);
        Assert.Contains(audit.Entries, e => e.Action == "LoginThrottled");
    }

    [Fact]
    public async Task ANewUsernameOnEveryAttempt_MeetsThePerAddressCeiling()
    {
        // Neither the username+address nor the username bucket ever filled, and each attempt cost a hash.
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new PasswordAttemptLimiter(cache, new FakeTimeProvider(new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero)));
        var audit = new RecordingAudit();

        for (var attempt = 0; attempt < LoginModel.AddressCeiling; attempt++)
        {
            var model = CreateModel(users, limiter, audit, "203.0.113.66");
            model.Input = new LoginModel.InputModel { Username = $"guess{attempt}", Password = "wrong" };
            await model.OnPostAsync(ct);
        }
        Assert.DoesNotContain(audit.Entries, e => e.Action == IdentityAuditActions.LoginThrottled);

        var sameAddress = await AttemptAsync(users, limiter, audit, "203.0.113.66", GoodPassword, ct);
        var otherAddress = await AttemptAsync(users, limiter, audit, "198.51.100.7", GoodPassword, ct);

        Assert.Equal("Invalid username or password.", sameAddress.ErrorMessage);
        Assert.Contains(audit.Entries, e => e.Action == IdentityAuditActions.LoginThrottled);
        Assert.Null(otherAddress.ErrorMessage);
    }

    [Fact]
    public async Task SuccessfulSignIns_DoNotUseUpTheAddressCeiling()
    {
        // Many people behind one address sign in all day; only failures count against it.
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        using var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new PasswordAttemptLimiter(cache, new FakeTimeProvider(new DateTimeOffset(2026, 11, 3, 9, 0, 0, TimeSpan.Zero)));
        var audit = new RecordingAudit();

        for (var attempt = 0; attempt < LoginModel.AddressCeiling + 5; attempt++)
            Assert.Null((await AttemptAsync(users, limiter, audit, "192.0.2.10", GoodPassword, ct)).ErrorMessage);
    }

    [Fact]
    public async Task SixthWrongPassword_IsThrottledWithTheSameMessage()
    {
        var ct = TestContext.Current.CancellationToken;
        var users = await CreateStoreAsync(ct);
        using var cache = new MemoryCache(new MemoryCacheOptions());
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
        using var cache = new MemoryCache(new MemoryCacheOptions());
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
