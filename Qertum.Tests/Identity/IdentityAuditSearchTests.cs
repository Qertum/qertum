using Qertum.IdentityService.Services.Audit;

namespace Qertum.Tests.Identity;

public sealed class IdentityAuditSearchTests
{
    private static async Task<string> WriteLogAsync(CancellationToken ct)
    {
        var directory = Directory.CreateTempSubdirectory("qertum-audit-search").FullName;
        var path = Path.Combine(directory, "identity-audit-20260915.clef");
        await File.WriteAllLinesAsync(path,
        [
            Line("2026-09-10T08:00:00.000Z", "UserCreated", "alice", "bob"),
            Line("2026-09-11T08:00:00.000Z", "RoleRenamed", "alice", "platform"),
            Line("2026-09-12T08:00:00.000Z", "UserDisabled", "carol", "bob")
        ], ct);
        return Path.Combine(directory, "identity-audit-.clef");
    }

    private static string Line(string timestamp, string action, string actor, string resource) =>
        $$"""{"@t":"{{timestamp}}","@mt":"Audit {Action} by {PerformedBy} on {ResourceName}","IsAuditEvent":true,"Action":"{{action}}","PerformedBy":"{{actor}}","ResourceName":"{{resource}}"}""";

    [Fact]
    public async Task FiltersCombineWithAnd()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new IdentityAuditLogReader(await WriteLogAsync(ct));

        var byAction = await reader.ReadAsync(new IdentityAuditQuery(Action: "RoleRenamed"), 0, 50, ct);
        Assert.Equal(["RoleRenamed"], byAction.Entries.Select(e => e.Action));

        var byActor = await reader.ReadAsync(new IdentityAuditQuery(Actor: "ALI"), 0, 50, ct);
        Assert.Equal(2, byActor.Entries.Count);

        var byRange = await reader.ReadAsync(
            new IdentityAuditQuery(From: new DateOnly(2026, 9, 11), To: new DateOnly(2026, 9, 11)), 0, 50, ct);
        Assert.Equal(["RoleRenamed"], byRange.Entries.Select(e => e.Action));

        var combined = await reader.ReadAsync(new IdentityAuditQuery(Actor: "alice", Action: "UserCreated"), 0, 50, ct);
        Assert.Single(combined.Entries);

        var byText = await reader.ReadAsync(new IdentityAuditQuery(Text: "platform"), 0, 50, ct);
        Assert.Single(byText.Entries);
    }

    [Fact]
    public async Task EmptyQuery_ReadsEverythingNewestFirst()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new IdentityAuditLogReader(await WriteLogAsync(ct));

        var page = await reader.ReadAsync(new IdentityAuditQuery(), 0, 50, ct);

        Assert.Equal(["UserDisabled", "RoleRenamed", "UserCreated"], page.Entries.Select(e => e.Action));
        Assert.False(page.HasOlder);
        Assert.False(page.Truncated);
    }

    [Fact]
    public async Task PagingStillWorksUnderAFilter()
    {
        var ct = TestContext.Current.CancellationToken;
        var reader = new IdentityAuditLogReader(await WriteLogAsync(ct));

        var first = await reader.ReadAsync(new IdentityAuditQuery(Actor: "alice"), 0, 1, ct);
        var second = await reader.ReadAsync(new IdentityAuditQuery(Actor: "alice"), 1, 1, ct);

        Assert.True(first.HasOlder);
        Assert.Equal("RoleRenamed", Assert.Single(first.Entries).Action);
        Assert.Equal("UserCreated", Assert.Single(second.Entries).Action);
        Assert.False(second.HasOlder);
    }
}
