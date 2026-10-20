using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Qertum.IdentityService.Stores;
using static Qertum.Tests.Identity.IdentityHostTestKit;

namespace Qertum.Tests.Identity;

public sealed class PasswordChangeThrottleHostTests
{
    [Fact]
    public async Task SixthCurrentPasswordAttemptIsThrottledUntilWindowExpires()
    {
        var ct = TestContext.Current.CancellationToken;
        var dataPath = Path.Combine(Path.GetTempPath(), $"idp-password-throttle-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dataPath);
        try
        {
            // The host creates OpenIddict certificates using system time; keep its fake clock
            // inside their validity window while still advancing the throttle window manually.
            var clock = new FakeTimeProvider(TimeProvider.System.GetUtcNow());
            using var factory = CreateFactory(dataPath, clock);
            const string currentPassword = "Current-Password-1!";
            await factory.Services.GetRequiredService<JsonUserStore>().CreateUserAsync(
                "alice", "alice@example.test", "Alice", currentPassword, [], false, ct);
            using var client = CreateClient(factory);
            await LoginAsync(client, "alice", currentPassword, ct);

            for (var attempt = 0; attempt < 5; attempt++)
            {
                using var wrong = await ChangeAsync(client, "wrong", ct);
                Assert.Equal(HttpStatusCode.OK, wrong.StatusCode);
                Assert.Contains("Current password is incorrect.", await wrong.Content.ReadAsStringAsync(ct));
            }

            using var blocked = await ChangeAsync(client, currentPassword, ct);
            Assert.Equal(HttpStatusCode.OK, blocked.StatusCode);
            Assert.Contains("Too many failed attempts", await blocked.Content.ReadAsStringAsync(ct));

            clock.Advance(TimeSpan.FromSeconds(61));
            using var afterWindow = await ChangeAsync(client, currentPassword, ct);
            Assert.Equal(HttpStatusCode.OK, afterWindow.StatusCode);
            Assert.Contains("Password updated.", await afterWindow.Content.ReadAsStringAsync(ct));
        }
        finally
        {
            try { Directory.Delete(dataPath, recursive: true); } catch { /* best effort */ }
        }
    }

    private static Task<HttpResponseMessage> ChangeAsync(HttpClient client, string currentPassword, CancellationToken ct)
        => PostFormAsync(client, "/Account/ChangePassword", "/Account/ChangePassword",
        [
            KeyValuePair.Create("Input.CurrentPassword", currentPassword),
            KeyValuePair.Create("Input.NewPassword", "New-Valid-Password-2!"),
            KeyValuePair.Create("Input.ConfirmPassword", "New-Valid-Password-2!")
        ], ct);
}
