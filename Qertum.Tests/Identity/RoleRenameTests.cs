using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Services.Admin;
using Qertum.IdentityService.Services.Audit;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

/// <summary>
/// Renaming a role has to move the catalog entry and every holder together, and the CA's grants are
/// deliberately not touched — the IdP never calls the CA.
/// </summary>
public sealed class RoleRenameTests
{
    private sealed class RecordingAuditLog : IIdentityAuditLog
    {
        public List<(string Action, string PerformedBy, Guid? ResourceId, string? ResourceName, string? Detail)> Entries { get; } = [];

        public void Write(string action, string performedBy, Guid? resourceId = null, string? resourceName = null, string? detail = null) =>
            Entries.Add((action, performedBy, resourceId, resourceName, detail));
    }

    private sealed class NoopGrantRevoker : IGrantRevoker
    {
        public Task RevokeAllAsync(Guid userId, CancellationToken cancellationToken) => Task.CompletedTask;
    }

    private sealed record Harness(
        UserAdministrationService Admin,
        JsonUserStore Users,
        JsonRoleStore Roles,
        RecordingAuditLog Audit,
        AdminActor Actor);

    private static async Task<Harness> CreateAsync(CancellationToken ct)
    {
        var dir = Path.Combine(Path.GetTempPath(), $"role-rename-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        var users = new JsonUserStore(NullLogger<JsonUserStore>.Instance, dir);
        var roles = new JsonRoleStore(dir);
        var audit = new RecordingAuditLog();
        var admin = (await users.FindByUsernameAsync("admin", ct))!;
        var service = new UserAdministrationService(users, roles, audit, new NoopGrantRevoker(), NullLogger<UserAdministrationService>.Instance);
        return new Harness(service, users, roles, audit, new AdminActor(admin.Id, admin.Username));
    }

    [Fact]
    public async Task Rename_UpdatesCatalogAndEveryHolder()
    {
        var ct = TestContext.Current.CancellationToken;
        var harness = await CreateAsync(ct);
        await harness.Roles.CreateAsync("ops", "Operators", ct);
        var user = await harness.Users.CreateUserAsync("bob", "bob@example.test", "Bob", "Rename-Test-Pass-1!", ["ops"], false, ct);

        var result = await harness.Roles.RenameAsync("ops", "platform", harness.Users.RenameRoleForAllAsync, ct);

        Assert.Equal(RoleStoreResult.Success, result);
        var catalog = await harness.Roles.GetAllAsync(ct);
        Assert.Contains(catalog, r => r.Name == "platform");
        Assert.DoesNotContain(catalog, r => r.Name == "ops");
        var stored = await harness.Users.FindByIdAsync(user.Id, ct);
        Assert.Equal(["platform"], stored!.Roles);
    }

    [Fact]
    public async Task Rename_RefusesBuiltInInvalidAndExisting()
    {
        var ct = TestContext.Current.CancellationToken;
        var harness = await CreateAsync(ct);
        await harness.Roles.CreateAsync("ops", "Operators", ct);
        await harness.Roles.CreateAsync("platform", "Platform", ct);

        Assert.Equal(RoleStoreResult.BuiltIn, await harness.Roles.RenameAsync("admin", "root", harness.Users.RenameRoleForAllAsync, ct));
        Assert.Equal(RoleStoreResult.InvalidName, await harness.Roles.RenameAsync("ops", "bad name", harness.Users.RenameRoleForAllAsync, ct));
        Assert.Equal(RoleStoreResult.AlreadyExists, await harness.Roles.RenameAsync("ops", "PLATFORM", harness.Users.RenameRoleForAllAsync, ct));
        Assert.Equal(RoleStoreResult.NotFound, await harness.Roles.RenameAsync("nobody", "someone", harness.Users.RenameRoleForAllAsync, ct));
    }

    [Fact]
    public async Task AdminService_AuditsOnceOnSuccessAndNeverOnRefusal()
    {
        var ct = TestContext.Current.CancellationToken;
        var harness = await CreateAsync(ct);
        await harness.Roles.CreateAsync("ops", "Operators", ct);

        var ok = await harness.Admin.RenameRoleAsync(harness.Actor, "ops", "platform", ct);
        var refused = await harness.Admin.RenameRoleAsync(harness.Actor, "admin", "root", ct);

        Assert.Equal(AdminResult.Success, ok.Result);
        Assert.Equal(AdminResult.BuiltInRole, refused.Result);
        Assert.Equal([("RoleRenamed", "platform")], harness.Audit.Entries.Select(e => (e.Action, e.ResourceName)));
    }
}
