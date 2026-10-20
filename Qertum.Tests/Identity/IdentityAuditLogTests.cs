using Microsoft.Extensions.Logging.Abstractions;
using Qertum.IdentityService.Configuration;
using Qertum.IdentityService.Services.Audit;

namespace Qertum.Tests.Identity;

public sealed class IdentityAuditLogTests
{
    private static string AuditPath(out string dir)
    {
        dir = Path.Combine(Path.GetTempPath(), $"idp-audit-{Guid.NewGuid():N}");
        return Path.Combine(dir, "audit-logs", "identity-audit-.clef");
    }

    [Fact]
    public async Task WrittenEntries_ReadBackNewestFirst_WithAllFields()
    {
        var ct = TestContext.Current.CancellationToken;
        var path = AuditPath(out _);
        var target = Guid.NewGuid();

        using (var log = new IdentityAuditLog(path, NullLogger<IdentityAuditLog>.Instance))
        {
            log.Write(IdentityAuditActions.UserCreated, "boss", target, "alice", "roles: viewer");
            log.Write(IdentityAuditActions.RoleCreated, "boss", resourceName: "auditor");
            log.Write(IdentityAuditActions.UserDisabled, "boss", target, "alice");
        }

        var entries = await new IdentityAuditLogReader(path).ReadAsync(0, 50, ct);

        Assert.Equal(
            [IdentityAuditActions.UserDisabled, IdentityAuditActions.RoleCreated, IdentityAuditActions.UserCreated],
            entries.Select(e => e.Action));
        var created = entries[2];
        Assert.Equal("boss", created.PerformedBy);
        Assert.Equal(target, created.ResourceId);
        Assert.Equal("alice", created.ResourceName);
        Assert.Equal("roles: viewer", created.Detail);
        Assert.Equal(DateTimeKind.Utc, created.OccurredAtUtc.Kind);
        Assert.Null(entries[1].ResourceId);
    }

    [Fact]
    public async Task SkipAndTake_PageThroughEntries()
    {
        var ct = TestContext.Current.CancellationToken;
        var path = AuditPath(out _);
        using (var log = new IdentityAuditLog(path, NullLogger<IdentityAuditLog>.Instance))
        {
            for (var i = 0; i < 5; i++)
            {
                log.Write(IdentityAuditActions.RoleUpdated, "boss", resourceName: $"role{i}");
            }
        }

        var reader = new IdentityAuditLogReader(path);

        Assert.Equal(["role4", "role3"], (await reader.ReadAsync(0, 2, ct)).Select(e => e.ResourceName));
        Assert.Equal(["role2", "role1"], (await reader.ReadAsync(2, 2, ct)).Select(e => e.ResourceName));
        Assert.Equal(["role0"], (await reader.ReadAsync(4, 2, ct)).Select(e => e.ResourceName));
    }

    [Fact]
    public async Task NonAuditAndMalformedLines_AreSkipped()
    {
        var ct = TestContext.Current.CancellationToken;
        var path = AuditPath(out var dir);
        using (var log = new IdentityAuditLog(path, NullLogger<IdentityAuditLog>.Instance))
        {
            log.Write(IdentityAuditActions.UserEnabled, "boss");
        }

        var file = Directory.GetFiles(Path.Combine(dir, "audit-logs")).Single();
        await File.AppendAllTextAsync(file, "{\"@t\":\"2026-09-14T00:00:00Z\",\"@mt\":\"not audit\"}\nnot json\n", ct);

        var entries = await new IdentityAuditLogReader(path).ReadAsync(0, 50, ct);

        Assert.Equal([IdentityAuditActions.UserEnabled], entries.Select(e => e.Action));
    }

    [Fact]
    public async Task NullPath_WritesNothingAndReadsEmpty()
    {
        using var log = new IdentityAuditLog(null, NullLogger<IdentityAuditLog>.Instance);
        log.Write(IdentityAuditActions.UserCreated, "boss");

        Assert.Empty(await new IdentityAuditLogReader(null).ReadAsync(0, 50, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task MissingDirectory_ReadsEmpty()
    {
        var path = AuditPath(out _);
        Assert.Empty(await new IdentityAuditLogReader(path).ReadAsync(0, 50, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void ResolveAuditLogPath_DefaultsUnderTheDataPath_AndHonoursOverride()
    {
        var dir = Path.Combine(Path.GetTempPath(), $"idp-opts-{Guid.NewGuid():N}");
        var options = new IdentityServiceOptions { DataPath = dir };

        Assert.Equal(Path.Combine(Path.GetFullPath(dir), "audit-logs", "identity-audit-.clef"), options.ResolveAuditLogPath());

        var custom = Path.Combine(dir, "elsewhere", "idp-.clef");
        options.AuditLog.Path = custom;
        Assert.Equal(Path.GetFullPath(custom), options.ResolveAuditLogPath());
    }
}
