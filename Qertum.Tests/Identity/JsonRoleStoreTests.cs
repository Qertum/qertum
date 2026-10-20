using System.Text.Json;
using Qertum.IdentityService.Models;
using Qertum.IdentityService.Stores;

namespace Qertum.Tests.Identity;

public sealed class JsonRoleStoreTests
{
    private static string TempDir()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"roles-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(dir);
        return dir;
    }

    private static JsonRoleStore CreateStore(string dir) => new(dir);

    [Fact]
    public async Task Seed_WritesOnlyTheBuiltInAdmin()
    {
        var store = CreateStore(TempDir());

        var role = Assert.Single(await store.GetAllAsync(TestContext.Current.CancellationToken));

        Assert.Equal("admin", role.Name);
        Assert.True(role.BuiltIn);
    }

    [Fact]
    public async Task Seed_ExistingFile_IsNotReseeded()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();
        var first = CreateStore(dir);
        Assert.Equal(RoleStoreResult.Success, await first.CreateAsync("auditor", "Reads logs.", ct));

        var second = new JsonRoleStore(dir);

        Assert.Equal(["admin", "auditor"], (await second.GetAllAsync(ct)).Select(r => r.Name));
    }

    [Fact]
    public async Task Load_HandRemovedAdmin_IsRestoredAsBuiltIn()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();
        var store = CreateStore(dir);
        await File.WriteAllTextAsync(store.FilePath,
            JsonSerializer.Serialize(new[] { new { name = "viewer", description = "", builtIn = false } }), ct);

        var roles = await store.GetAllAsync(ct);

        Assert.Equal("admin", roles[0].Name);
        Assert.True(roles[0].BuiltIn);
        Assert.Contains(roles, r => r.Name == "viewer");
    }

    [Theory]
    [InlineData("")]
    [InlineData("has space")]
    [InlineData("é")]
    [InlineData("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")] // 65 chars
    public async Task Create_InvalidName_IsRefused(string name)
    {
        var store = CreateStore(TempDir());
        Assert.Equal(RoleStoreResult.InvalidName, await store.CreateAsync(name, "", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Create_DuplicateIgnoringCase_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = CreateStore(TempDir());
        Assert.Equal(RoleStoreResult.Success, await store.CreateAsync("viewer", "", ct));
        Assert.Equal(RoleStoreResult.AlreadyExists, await store.CreateAsync("VIEWER", "", ct));
        Assert.Equal(RoleStoreResult.AlreadyExists, await store.CreateAsync("Admin", "", ct));
    }

    [Fact]
    public async Task CreateAndUpdate_DescriptionTooLong_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = CreateStore(TempDir());
        var tooLong = new string('x', JsonRoleStore.MaxDescriptionLength + 1);

        Assert.Equal(RoleStoreResult.DescriptionTooLong, await store.CreateAsync("viewer", tooLong, ct));
        Assert.Equal(RoleStoreResult.Success, await store.CreateAsync("viewer", "ok", ct));
        Assert.Equal(RoleStoreResult.DescriptionTooLong, await store.UpdateDescriptionAsync("viewer", tooLong, ct));
    }

    [Fact]
    public async Task UpdateDescription_PersistsAndUnknownIsNotFound()
    {
        var ct = TestContext.Current.CancellationToken;
        var dir = TempDir();
        var store = CreateStore(dir);
        await store.CreateAsync("viewer", "", ct);

        Assert.Equal(RoleStoreResult.Success, await store.UpdateDescriptionAsync("VIEWER", "Can view.", ct));
        Assert.Equal(RoleStoreResult.NotFound, await store.UpdateDescriptionAsync("ghost", "x", ct));

        var reloaded = new JsonRoleStore(dir);
        Assert.Equal("Can view.", (await reloaded.GetAllAsync(ct)).Single(r => r.Name == "viewer").Description);
    }

    [Fact]
    public async Task Delete_Admin_IsRefusedAsBuiltIn()
    {
        var store = CreateStore(TempDir());
        var result = await store.DeleteAsync("admin", (_, _) => Task.FromResult(false), TestContext.Current.CancellationToken);
        Assert.Equal(RoleStoreResult.BuiltIn, result);
    }

    [Fact]
    public async Task Delete_HeldRole_IsRefusedAndKept()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = CreateStore(TempDir());
        await store.CreateAsync("viewer", "", ct);

        Assert.Equal(RoleStoreResult.InUse, await store.DeleteAsync("viewer", (_, _) => Task.FromResult(true), ct));
        Assert.Contains(await store.GetAllAsync(ct), r => r.Name == "viewer");
    }

    [Fact]
    public async Task Delete_UnheldRole_IsRemoved()
    {
        var ct = TestContext.Current.CancellationToken;
        var store = CreateStore(TempDir());
        await store.CreateAsync("viewer", "", ct);

        Assert.Equal(RoleStoreResult.Success, await store.DeleteAsync("Viewer", (_, _) => Task.FromResult(false), ct));
        Assert.DoesNotContain(await store.GetAllAsync(ct), r => r.Name == "viewer");
        Assert.Equal(RoleStoreResult.NotFound, await store.DeleteAsync("viewer", (_, _) => Task.FromResult(false), ct));
    }
}
