using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class AcmeOrderQueryTests
{
    [Fact]
    public async Task List_SearchesIdentifiersAndReportsTheLastFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var account = new AcmeAccount { JwkThumbprint = "t", PublicKeyJwk = "{}" };
        var failing = Order(account.Id, "fails.example.com");
        var fine = Order(account.Id, "fine.example.com");
        db.AcmeAccounts.Add(account);
        db.AcmeOrders.AddRange(failing, fine);
        db.LifecycleEvents.AddRange(
            AttemptFailed(failing.Id, "DnsNoTxtRecord", "No TXT record found at '_acme-challenge.fails.example.com'.", DateTime.UtcNow.AddMinutes(-2)),
            AttemptFailed(failing.Id, "Timeout", "Timeout reaching http://fails.example.com/.well-known/acme-challenge/<token>", DateTime.UtcNow.AddMinutes(-1)));
        await db.SaveChangesAsync(ct);
        var service = new AcmeOrderQueryService(db);

        var searched = await service.ListAsync("FAILS", failingOnly: false, 1, 50, ct);
        var failingOnly = await service.ListAsync(null, failingOnly: true, 1, 50, ct);

        var item = Assert.Single(searched.Items);
        Assert.Equal(failing.Id, item.Id);
        Assert.Equal(["fails.example.com"], item.Identifiers);
        Assert.Equal("Timeout", item.LastFailureCategory);
        Assert.Equal(failing.Id, Assert.Single(failingOnly.Items).Id);
    }

    [Fact]
    public async Task Detail_ShowsAuthorizationsChallengesAndHistoryWithHints()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();
        var account = new AcmeAccount { JwkThumbprint = "t", PublicKeyJwk = "{}" };
        var order = Order(account.Id, "detail.example.com");
        var auth = new AcmeAuthorization { OrderId = order.Id, IdentifierValue = "detail.example.com", ExpiresAtUtc = DateTime.UtcNow.AddDays(1) };
        db.AcmeAccounts.Add(account);
        db.AcmeOrders.Add(order);
        db.AcmeAuthorizations.Add(auth);
        db.AcmeChallenges.Add(new AcmeChallenge { AuthorizationId = auth.Id, Type = "dns-01", Token = "secret-token", Status = "processing", ValidationAttempts = 1 });
        db.LifecycleEvents.Add(AttemptFailed(order.Id, "DnsNoTxtRecord", "No TXT record.", DateTime.UtcNow));
        await db.SaveChangesAsync(ct);

        var detail = (await new AcmeOrderQueryService(db).GetAsync(order.Id, ct))!;

        var authorization = Assert.Single(detail.Authorizations);
        Assert.Equal("detail.example.com", authorization.Identifier);
        var challenge = Assert.Single(authorization.Challenges);
        Assert.Equal(("dns-01", 1), (challenge.Type, challenge.Attempts));
        var entry = Assert.Single(detail.History);
        Assert.Equal(DiagnosticHints.For("DnsNoTxtRecord"), entry.Hint);
        Assert.DoesNotContain("secret-token", System.Text.Json.JsonSerializer.Serialize(detail));
    }

    [Fact]
    public async Task Detail_ForAnUnknownOrder_IsNull()
    {
        var ct = TestContext.Current.CancellationToken;
        var database = SharedInMemoryDatabase.Create(createSchema: true);
        await using var db = database.CreateContext();

        Assert.Null(await new AcmeOrderQueryService(db).GetAsync(Guid.NewGuid(), ct));
    }

    private static AcmeOrder Order(Guid accountId, string name) => new()
    {
        AccountId = accountId,
        IdentifiersJson = $$"""[{"type":"dns","value":"{{name}}"}]""",
        ExpiresAtUtc = DateTime.UtcNow.AddDays(7)
    };

    private static LifecycleEvent AttemptFailed(Guid orderId, string category, string detail, DateTime at) => new()
    {
        Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, OccurredAtUtc = at,
        SubjectType = LifecycleSubjectTypes.AcmeOrder, SubjectId = orderId,
        Action = DiagnosticActions.ChallengeAttemptFailed, Category = category, Detail = detail, PerformedBy = "system"
    };
}
