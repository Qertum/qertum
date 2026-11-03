using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

/// <summary>
/// Self-service writes (password change, rehash on sign-in, profile) read the user, then replaced the whole record or
/// added it back when missing. An administrator's reset, disable or delete made in between was undone, and a deleted
/// account came back (AI Scan #341 on 1.0.0-rc4.2). The hasher here runs the administrator's change at the moment the
/// self-service path hashes, between its read and its write; a second store over the same file stands in for the admin.
/// </summary>
public sealed class UserStoreSelfServiceRaceTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("qertum-userrace-").FullName;
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch (IOException) { /* best effort */ }
    }

    private sealed class InterleavingHasher : IPasswordHasher<StoredUser>
    {
        private readonly PasswordHasher<StoredUser> _inner = new();
        public Func<Task>? DuringNextHash { get; set; }
        public bool ForceRehash { get; set; }

        public string HashPassword(StoredUser user, string password)
        {
            if (DuringNextHash is { } act)
            {
                DuringNextHash = null;
                act().GetAwaiter().GetResult();
            }
            return _inner.HashPassword(user, password);
        }

        public PasswordVerificationResult VerifyHashedPassword(StoredUser user, string hashedPassword, string providedPassword)
        {
            var result = _inner.VerifyHashedPassword(user, hashedPassword, providedPassword);
            return ForceRehash && result == PasswordVerificationResult.Success ? PasswordVerificationResult.SuccessRehashNeeded : result;
        }
    }

    private (JsonUserStore Self, JsonUserStore Admin, InterleavingHasher Hasher) Stores()
    {
        var hasher = new InterleavingHasher();
        var self = new JsonUserStore(NullLogger<JsonUserStore>.Instance, _dir, "seed-admin-pass", false, hasher);
        var admin = new JsonUserStore(NullLogger<JsonUserStore>.Instance, _dir);
        return (self, admin, hasher);
    }

    [Fact]
    public async Task APasswordChange_DoesNotUndoAnAdminResetMadeMeanwhile()
    {
        var (self, admin, hasher) = Stores();
        var user = await admin.CreateUserAsync("alice", "a@example.test", "Alice", "old-password-1", ["viewer"], cancellationToken: Ct);
        hasher.DuringNextHash = () => admin.ResetPasswordAsync(user.Id, "reset-password-1", Ct);

        var result = await self.ChangePasswordAsync(user.Id, "old-password-1", "new-password-1", Ct);

        Assert.Equal(JsonUserStore.ChangePasswordResult.CurrentPasswordIncorrect, result);
        Assert.NotNull(await admin.ValidateCredentialsAsync("alice", "reset-password-1", Ct));
        Assert.Null(await admin.ValidateCredentialsAsync("alice", "new-password-1", Ct));
        Assert.True((await admin.FindByIdAsync(user.Id, Ct))!.MustChangePassword);
    }

    [Fact]
    public async Task ARehashOnSignIn_DoesNotBringBackAUserDeletedMeanwhile()
    {
        var (self, admin, hasher) = Stores();
        var user = await admin.CreateUserAsync("bob", "b@example.test", "Bob", "bob-password-1", ["viewer"], cancellationToken: Ct);
        hasher.ForceRehash = true;
        hasher.DuringNextHash = () => admin.RemoveAsync(user.Id, Ct);

        await self.ValidateCredentialsAsync("bob", "bob-password-1", Ct);

        Assert.Null(await admin.FindByIdAsync(user.Id, Ct));
    }

    [Fact]
    public async Task ARehashOnSignIn_DoesNotUndoADisableMadeMeanwhile()
    {
        var (self, admin, hasher) = Stores();
        var user = await admin.CreateUserAsync("carol", "c@example.test", "Carol", "carol-password-1", ["viewer"], cancellationToken: Ct);
        hasher.ForceRehash = true;
        hasher.DuringNextHash = () => admin.SetDisabledAsync(user.Id, true, Ct);

        await self.ValidateCredentialsAsync("carol", "carol-password-1", Ct);

        Assert.True((await admin.FindByIdAsync(user.Id, Ct))!.IsDisabled);
    }

    [Fact]
    public async Task AProfileUpdate_KeepsRolesChangedMeanwhile_AndNeverAddsADeletedUser()
    {
        var (self, admin, _) = Stores();
        var user = await admin.CreateUserAsync("dave", "d@example.test", "Dave", "dave-password-1", ["viewer", "operator"], cancellationToken: Ct);
        await admin.UpdateRolesAsync(user.Id, ["viewer"], Ct);

        await self.UpdateProfileAsync(user.Id, "Dave D", "dave@example.test", Ct);
        var stored = (await admin.FindByIdAsync(user.Id, Ct))!;
        Assert.Equal(["viewer"], stored.Roles);
        Assert.Equal("Dave D", stored.DisplayName);

        await admin.RemoveAsync(user.Id, Ct);
        await Assert.ThrowsAsync<InvalidOperationException>(() => self.UpdateProfileAsync(user.Id, "X", "x@example.test", Ct));
        Assert.Null(await admin.FindByIdAsync(user.Id, Ct));
    }
}
