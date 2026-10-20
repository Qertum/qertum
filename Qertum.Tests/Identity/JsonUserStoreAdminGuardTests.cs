using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

public sealed class JsonUserStoreAdminGuardTests
{
    private const string Password = "Guard-Test-Pass-1!";

    private static JsonUserStore NewStore(out string dir)
    {
        dir = Path.Combine(Path.GetTempPath(), $"guard-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
    }

    private static async Task<StoredUser> SeededAdminAsync(JsonUserStore store, CancellationToken ct) =>
        (await store.FindByUsernameAsync("admin", ct))!;

    [Fact]
    public async Task RemovingAdminRoleFromOnlyAdmin_IsRefusedAndNothingIsWritten()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var admin = await SeededAdminAsync(store, ct);

        Assert.Equal(UserMutationResult.WouldRemoveLastAdmin, await store.MutateAsync(admin.Id, u => u.Roles = [], ct));
        Assert.Contains("admin", (await store.FindByIdAsync(admin.Id, ct))!.Roles);
    }

    [Fact]
    public async Task DisablingOnlyAdmin_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var admin = await SeededAdminAsync(store, ct);

        Assert.Equal(UserMutationResult.WouldRemoveLastAdmin, await store.MutateAsync(admin.Id, u => u.IsDisabled = true, ct));
        Assert.False((await store.FindByIdAsync(admin.Id, ct))!.IsDisabled);
    }

    [Fact]
    public async Task RemovingOnlyAdmin_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var admin = await SeededAdminAsync(store, ct);

        Assert.Equal(UserMutationResult.WouldRemoveLastAdmin, await store.RemoveAsync(admin.Id, ct));
        Assert.NotNull(await store.FindByIdAsync(admin.Id, ct));
    }

    [Fact]
    public async Task AdminRoleComparison_IgnoresCase()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var admin = await SeededAdminAsync(store, ct);
        var other = await store.CreateUserAsync("upper", "u@t.local", "U", Password, ["ADMIN"], cancellationToken: ct);

        Assert.Equal(UserMutationResult.Updated, await store.MutateAsync(admin.Id, u => u.IsDisabled = true, ct));
        Assert.Equal(UserMutationResult.WouldRemoveLastAdmin, await store.MutateAsync(other.Id, u => u.IsDisabled = true, ct));
    }

    [Fact]
    public async Task WithAnotherEnabledAdmin_ChangesAreAllowed()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var admin = await SeededAdminAsync(store, ct);
        await store.CreateUserAsync("second", "s@t.local", "S", Password, ["admin"], cancellationToken: ct);

        Assert.Equal(UserMutationResult.Updated, await store.RemoveAsync(admin.Id, ct));
        Assert.Null(await store.FindByIdAsync(admin.Id, ct));
    }

    [Fact]
    public async Task UnknownUser_IsNotFound()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);

        Assert.Equal(UserMutationResult.NotFound, await store.MutateAsync(Guid.NewGuid(), _ => { }, ct));
        Assert.Equal(UserMutationResult.NotFound, await store.RemoveAsync(Guid.NewGuid(), ct));
        Assert.Equal(UserMutationResult.NotFound, await store.ResetPasswordAsync(Guid.NewGuid(), Password, ct));
    }

    [Fact]
    public async Task FileWithZeroEnabledAdmins_DoesNotBlockUnrelatedChanges_AndAllowsReEnabling()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var admin = await SeededAdminAsync(store, ct);
        var user = await store.CreateUserAsync("plain", "p@t.local", "P", Password, ["viewer"], cancellationToken: ct);

        var users = await store.GetAllAsync(ct);
        users.Single(u => u.Id == admin.Id).IsDisabled = true;
        await File.WriteAllTextAsync(store.FilePath, JsonSerializer.Serialize(users), ct);

        Assert.Equal(UserMutationResult.Updated, await store.MutateAsync(user.Id, u => u.DisplayName = "Renamed", ct));
        Assert.Equal(UserMutationResult.Updated, await store.MutateAsync(admin.Id, u => u.IsDisabled = false, ct));
    }

    [Fact]
    public async Task ThrowingWrappers_ThrowWhenTheGuardRefuses()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var admin = await SeededAdminAsync(store, ct);

        var roles = await Assert.ThrowsAsync<InvalidOperationException>(() => store.UpdateRolesAsync(admin.Id, [], ct));
        Assert.Equal("This would leave no enabled administrator.", roles.Message);
        await Assert.ThrowsAsync<InvalidOperationException>(() => store.SetDisabledAsync(admin.Id, true, ct));
        var missing = await Assert.ThrowsAsync<InvalidOperationException>(() => store.UpdateRolesAsync(Guid.NewGuid(), [], ct));
        Assert.Equal("User not found.", missing.Message);
    }

    [Fact]
    public async Task ResetPassword_SetsNewPassword_FlagsChange_AndRotatesStamp()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var user = await store.CreateUserAsync("resetme", "r@t.local", "R", Password, ["viewer"], cancellationToken: ct);

        Assert.Equal(UserMutationResult.Updated, await store.ResetPasswordAsync(user.Id, "Brand-New-Pass-2!", ct));

        var reloaded = (await store.FindByIdAsync(user.Id, ct))!;
        Assert.True(reloaded.MustChangePassword);
        Assert.NotEqual(user.SecurityStamp, reloaded.SecurityStamp);
        Assert.Null(await store.ValidateCredentialsAsync("resetme", Password, ct));
        Assert.NotNull(await store.ValidateCredentialsAsync("resetme", "Brand-New-Pass-2!", ct));
    }

    [Fact]
    public async Task VerifyPassword_TrueOnlyForCorrectPasswordOfActiveUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = NewStore(out _);
        var user = await store.CreateUserAsync("verify", "v@t.local", "V", Password, ["viewer"], cancellationToken: ct);

        Assert.True(await store.VerifyPasswordAsync(user.Id, Password, ct));
        Assert.False(await store.VerifyPasswordAsync(user.Id, "wrong", ct));
        Assert.False(await store.VerifyPasswordAsync(Guid.NewGuid(), Password, ct));

        await store.SetDisabledAsync(user.Id, true, ct);
        Assert.False(await store.VerifyPasswordAsync(user.Id, Password, ct));
    }

    [Fact]
    public async Task TwoAdminsDisablingEachOtherConcurrently_ExactlyOneSucceeds()
    {
        var ct = TestContext.Current.CancellationToken;
        for (var i = 0; i < 25; i++)
        {
            var store = NewStore(out _);
            var first = await SeededAdminAsync(store, ct);
            var second = await store.CreateUserAsync("second", "s@t.local", "S", Password, ["admin"], cancellationToken: ct);

            var results = await Task.WhenAll(
                Task.Run(() => store.MutateAsync(second.Id, u => u.IsDisabled = true, ct), ct),
                Task.Run(() => store.MutateAsync(first.Id, u => u.IsDisabled = true, ct), ct));

            Assert.Single(results, r => r == UserMutationResult.Updated);
            Assert.Single(results, r => r == UserMutationResult.WouldRemoveLastAdmin);
            Assert.Equal(1, JsonUserStore.CountEnabledAdmins(await store.GetAllAsync(ct)));
        }
    }
}
