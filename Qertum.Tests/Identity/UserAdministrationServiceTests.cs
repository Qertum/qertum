using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Services.Admin;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

public sealed class UserAdministrationServiceTests
{
    private const string Password = "Service-Test-Pass-1!";

    private sealed class RecordingAuditLog : IIdentityAuditLog
    {
        public List<(string Action, string PerformedBy, Guid? ResourceId, string? ResourceName, string? Detail)> Entries { get; } = [];

        public void Write(string action, string performedBy, Guid? resourceId = null, string? resourceName = null, string? detail = null) =>
            Entries.Add((action, performedBy, resourceId, resourceName, detail));
    }

    private sealed class FakeGrantRevoker : IGrantRevoker
    {
        public bool Throw { get; set; }
        public List<Guid> Revoked { get; } = [];

        public Task RevokeAllAsync(Guid userId, CancellationToken cancellationToken)
        {
            if (Throw)
            {
                throw new InvalidOperationException("store unavailable");
            }

            Revoked.Add(userId);
            return Task.CompletedTask;
        }
    }

    private sealed record Harness(
        UserAdministrationService Service,
        JsonUserStore Users,
        JsonRoleStore Roles,
        RecordingAuditLog Audit,
        FakeGrantRevoker Revoker,
        AdminActor Actor);

    private static async Task<Harness> CreateAsync(CancellationToken ct)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"admin-svc-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var users = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        var roles = new JsonRoleStore(dir);
        await roles.CreateAsync("viewer", "Can view.", ct);
        var audit = new RecordingAuditLog();
        var revoker = new FakeGrantRevoker();
        var admin = (await users.FindByUsernameAsync("admin", ct))!;
        var service = new UserAdministrationService(users, roles, audit, revoker, NullLogger<UserAdministrationService>.Instance);
        return new Harness(service, users, roles, audit, revoker, new AdminActor(admin.Id, admin.Username));
    }

    [Fact]
    public async Task CreateUser_ReturnsUsableOneTimePassword_ForcesChange_AndAudits()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);

        var outcome = await h.Service.CreateUserAsync(h.Actor, "alice", "a@t.local", "Alice", ["viewer"], ct);

        Assert.Equal(AdminResult.Success, outcome.Result);
        Assert.NotNull(outcome.OneTimePassword);
        var created = await h.Users.ValidateCredentialsAsync("alice", outcome.OneTimePassword!, ct);
        Assert.NotNull(created);
        Assert.True(created!.MustChangePassword);
        Assert.Equal(["viewer"], created.Roles);

        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal(IdentityAuditActions.UserCreated, entry.Action);
        Assert.Equal("admin", entry.PerformedBy);
        Assert.Equal(created.Id, entry.ResourceId);
        Assert.Equal("alice", entry.ResourceName);
        Assert.DoesNotContain(outcome.OneTimePassword!, entry.Detail ?? string.Empty);
    }

    [Fact]
    public async Task CreateUser_StoresTheCatalogSpellingOfRoles()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);

        await h.Service.CreateUserAsync(h.Actor, "bob", "b@t.local", "Bob", ["VIEWER", "viewer"], ct);

        Assert.Equal(["viewer"], (await h.Users.FindByUsernameAsync("bob", ct))!.Roles);
    }

    [Fact]
    public async Task CreateUser_UnknownRole_IsRefused_CreatesNothing_AndIsNotAudited()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);

        var outcome = await h.Service.CreateUserAsync(h.Actor, "carol", "c@t.local", "Carol", ["viewer", "ghost"], ct);

        Assert.Equal(AdminResult.UnknownRole, outcome.Result);
        Assert.Null(outcome.OneTimePassword);
        Assert.Null(await h.Users.FindByUsernameAsync("carol", ct));
        Assert.Empty(h.Audit.Entries);
    }

    [Fact]
    public async Task CreateUser_TakenUsername_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);

        Assert.Equal(AdminResult.UsernameTaken, (await h.Service.CreateUserAsync(h.Actor, "ADMIN", "x@t.local", "X", [], ct)).Result);
    }

    [Fact]
    public async Task SetRoles_RemovingOwnAdmin_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        await h.Users.CreateUserAsync("other", "o@t.local", "O", Password, ["admin"], cancellationToken: ct);

        var outcome = await h.Service.SetRolesAsync(h.Actor, h.Actor.Id, ["viewer"], ct);

        Assert.Equal(AdminResult.WouldRemoveOwnAdmin, outcome.Result);
        Assert.Contains("admin", (await h.Users.FindByIdAsync(h.Actor.Id, ct))!.Roles);
        Assert.Empty(h.Audit.Entries);
    }

    [Fact]
    public async Task SetRoles_OnLastEnabledAdmin_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        var disabledAdmin = await h.Users.CreateUserAsync("dormant", "d@t.local", "D", Password, ["admin"], cancellationToken: ct);
        await h.Users.SetDisabledAsync(disabledAdmin.Id, true, ct);
        var actor = new AdminActor(disabledAdmin.Id, disabledAdmin.Username);

        Assert.Equal(AdminResult.WouldRemoveLastAdmin, (await h.Service.SetRolesAsync(actor, h.Actor.Id, [], ct)).Result);
    }

    [Fact]
    public async Task SetRoles_UnknownRole_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        var user = await h.Users.CreateUserAsync("dave", "d@t.local", "D", Password, ["viewer"], cancellationToken: ct);

        Assert.Equal(AdminResult.UnknownRole, (await h.Service.SetRolesAsync(h.Actor, user.Id, ["ghost"], ct)).Result);
        Assert.Equal(["viewer"], (await h.Users.FindByIdAsync(user.Id, ct))!.Roles);
    }

    [Fact]
    public async Task SetRoles_AuditsAddedAndRemoved()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        await h.Roles.CreateAsync("auditor", "", ct);
        var user = await h.Users.CreateUserAsync("erin", "e@t.local", "E", Password, ["viewer"], cancellationToken: ct);

        Assert.Equal(AdminResult.Success, (await h.Service.SetRolesAsync(h.Actor, user.Id, ["auditor"], ct)).Result);

        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal(IdentityAuditActions.UserRolesChanged, entry.Action);
        Assert.Equal("added: auditor; removed: viewer", entry.Detail);
    }

    [Fact]
    public async Task SetDisabled_Self_IsRefused_Other_IsAudited()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        var user = await h.Users.CreateUserAsync("frank", "f@t.local", "F", Password, ["viewer"], cancellationToken: ct);

        Assert.Equal(AdminResult.SelfTarget, (await h.Service.SetDisabledAsync(h.Actor, h.Actor.Id, true, ct)).Result);
        Assert.Equal(AdminResult.Success, (await h.Service.SetDisabledAsync(h.Actor, user.Id, true, ct)).Result);
        Assert.Equal(AdminResult.Success, (await h.Service.SetDisabledAsync(h.Actor, user.Id, false, ct)).Result);

        Assert.Equal([IdentityAuditActions.UserDisabled, IdentityAuditActions.UserEnabled], h.Audit.Entries.Select(e => e.Action));
    }

    [Fact]
    public async Task ResetPassword_Self_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);

        Assert.Equal(AdminResult.SelfTarget, (await h.Service.ResetPasswordAsync(h.Actor, h.Actor.Id, ct)).Result);
    }

    [Fact]
    public async Task ResetPassword_Other_ReturnsOneTimePassword_RotatesStamp_AndAudits()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        var user = await h.Users.CreateUserAsync("gina", "g@t.local", "G", Password, ["viewer"], cancellationToken: ct);

        var outcome = await h.Service.ResetPasswordAsync(h.Actor, user.Id, ct);

        Assert.Equal(AdminResult.Success, outcome.Result);
        var reloaded = await h.Users.ValidateCredentialsAsync("gina", outcome.OneTimePassword!, ct);
        Assert.NotNull(reloaded);
        Assert.True(reloaded!.MustChangePassword);
        Assert.NotEqual(user.SecurityStamp, reloaded.SecurityStamp);
        Assert.Equal(IdentityAuditActions.UserCredentialReset, Assert.Single(h.Audit.Entries).Action);
    }

    [Fact]
    public async Task DeleteUser_Self_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);

        Assert.Equal(AdminResult.SelfTarget, (await h.Service.DeleteUserAsync(h.Actor, h.Actor.Id, ct)).Result);
        Assert.Empty(h.Revoker.Revoked);
    }

    [Fact]
    public async Task DeleteUser_RemovesRevokesAndAudits()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        var user = await h.Users.CreateUserAsync("hank", "h@t.local", "H", Password, ["viewer"], cancellationToken: ct);

        Assert.Equal(AdminResult.Success, (await h.Service.DeleteUserAsync(h.Actor, user.Id, ct)).Result);

        Assert.Null(await h.Users.FindByIdAsync(user.Id, ct));
        Assert.Equal([user.Id], h.Revoker.Revoked);
        var entry = Assert.Single(h.Audit.Entries);
        Assert.Equal(IdentityAuditActions.UserDeleted, entry.Action);
        Assert.Equal("hank", entry.ResourceName);
        Assert.Null(entry.Detail);
    }

    [Fact]
    public async Task DeleteUser_RevocationFails_UserStaysDeleted_AndResultSaysSo()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        h.Revoker.Throw = true;
        var user = await h.Users.CreateUserAsync("ivy", "i@t.local", "I", Password, ["viewer"], cancellationToken: ct);

        var outcome = await h.Service.DeleteUserAsync(h.Actor, user.Id, ct);

        Assert.Equal(AdminResult.DeletedButRevocationIncomplete, outcome.Result);
        Assert.True(outcome.Succeeded);
        Assert.Null(await h.Users.FindByIdAsync(user.Id, ct));
        Assert.Equal("stored grants could not all be revoked", Assert.Single(h.Audit.Entries).Detail);
    }

    [Fact]
    public async Task Roles_CreateUpdateDelete_AreAudited()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);

        Assert.Equal(AdminResult.Success, (await h.Service.CreateRoleAsync(h.Actor, "auditor", "Reads logs.", ct)).Result);
        Assert.Equal(AdminResult.Success, (await h.Service.UpdateRoleAsync(h.Actor, "auditor", "Reads audit logs.", ct)).Result);
        Assert.Equal(AdminResult.Success, (await h.Service.DeleteRoleAsync(h.Actor, "auditor", ct)).Result);

        Assert.Equal(
            [IdentityAuditActions.RoleCreated, IdentityAuditActions.RoleUpdated, IdentityAuditActions.RoleDeleted],
            h.Audit.Entries.Select(e => e.Action));
        Assert.All(h.Audit.Entries, e => Assert.Equal("auditor", e.ResourceName));
    }

    [Fact]
    public async Task Roles_Refusals_MapToResults_AndAreNotAudited()
    {
        var ct = TestContext.Current.CancellationToken;
        var h = await CreateAsync(ct);
        await h.Users.CreateUserAsync("jack", "j@t.local", "J", Password, ["Viewer"], cancellationToken: ct);

        Assert.Equal(AdminResult.InvalidRoleName, (await h.Service.CreateRoleAsync(h.Actor, "bad name", "", ct)).Result);
        Assert.Equal(AdminResult.RoleExists, (await h.Service.CreateRoleAsync(h.Actor, "VIEWER", "", ct)).Result);
        Assert.Equal(AdminResult.DescriptionTooLong, (await h.Service.CreateRoleAsync(h.Actor, "long", new string('x', 501), ct)).Result);
        Assert.Equal(AdminResult.NotFound, (await h.Service.UpdateRoleAsync(h.Actor, "ghost", "", ct)).Result);
        Assert.Equal(AdminResult.BuiltInRole, (await h.Service.DeleteRoleAsync(h.Actor, "admin", ct)).Result);
        Assert.Equal(AdminResult.RoleInUse, (await h.Service.DeleteRoleAsync(h.Actor, "viewer", ct)).Result);
        Assert.Empty(h.Audit.Entries);
    }

    [Fact]
    public void OneTimePassword_HasTheSpecifiedLengthAndAlphabet_AndVaries()
    {
        var samples = Enumerable.Range(0, 50).Select(_ => OneTimePassword.Generate()).ToList();

        Assert.All(samples, s =>
        {
            Assert.Equal(20, s.Length);
            Assert.All(s, c => Assert.Contains(c, OneTimePassword.Alphabet));
        });
        Assert.Equal(samples.Count, samples.Distinct().Count());
        Assert.DoesNotContain('0', OneTimePassword.Alphabet);
        Assert.DoesNotContain('O', OneTimePassword.Alphabet);
        Assert.DoesNotContain('1', OneTimePassword.Alphabet);
        Assert.DoesNotContain('l', OneTimePassword.Alphabet);
        Assert.DoesNotContain('I', OneTimePassword.Alphabet);
    }

    [Fact]
    public void EveryResult_HasAFixedMessage()
    {
        foreach (var result in Enum.GetValues<AdminResult>())
        {
            Assert.False(string.IsNullOrWhiteSpace(AdminMessages.For(result)));
        }
    }
}
