using Qertum.Services;

namespace Qertum.Tests.Dashboard;

public sealed partial class AttentionServiceTests
{
    private static Webhook Hook(string name) => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        Url = "https://receiver.example.com/hook",
        CreatedAtUtc = NowUtc.AddDays(-30),
        UpdatedAtUtc = NowUtc.AddDays(-30)
    };

    private static WebhookDelivery Delivery(Webhook hook, string status, DateTime createdAtUtc, string? error = null) => new()
    {
        Id = Guid.NewGuid(),
        WebhookId = hook.Id,
        EventType = "Issued",
        Payload = """{"secret-looking":"payload"}""",
        ResolvedUrl = "https://receiver.example.com/hook?cn=private.example.com",
        Status = status,
        AttemptCount = 5,
        CreatedAtUtc = createdAtUtc,
        NextAttemptAfterUtc = createdAtUtc,
        LastErrorMessage = error
    };

    [Fact]
    public async Task FailedWebhooks_GroupsPerWebhookInsideTheWindow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        var ops = Hook("ops-alerts");
        var siem = Hook("siem");
        scope.Db.Webhooks.AddRange(ops, siem);
        scope.Db.WebhookDeliveries.AddRange(
            Delivery(ops, "Failed", NowUtc.AddDays(-3), "HTTP 500"),
            Delivery(ops, "Failed", NowUtc.AddDays(-1), "HTTP 502 Bad Gateway"),
            Delivery(siem, "Failed", NowUtc.AddDays(-2), "Connection refused"),
            Delivery(siem, "Delivered", NowUtc.AddDays(-1)),
            Delivery(siem, "Pending", NowUtc.AddDays(-1)),
            Delivery(ops, "Failed", NowUtc.AddDays(-9), "too old"));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.FailedWebhookDeliveries);
        Assert.Equal(3, item.Count);
        Assert.Equal(2, item.Evidence.Count);
        Assert.Equal("ops-alerts", item.Evidence[0].Label);
        Assert.Contains("2 failed", item.Evidence[0].Detail);
        Assert.Contains("HTTP 502 Bad Gateway", item.Evidence[0].Detail);
        Assert.Equal("siem", item.Evidence[1].Label);
        Assert.Equal("/webhooks", item.ActionHref);
    }

    [Fact]
    public async Task FailedWebhooks_EvidenceNeverCarriesPayloadOrResolvedUrl()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await AttentionTestDb.CreateAsync(ct);
        var hook = Hook("ops-alerts");
        scope.Db.Webhooks.Add(hook);
        scope.Db.WebhookDeliveries.Add(Delivery(hook, "Failed", NowUtc.AddDays(-1), "HTTP 500"));
        await scope.Db.SaveChangesAsync(ct);

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.Everything, ct);

        var item = Assert.Single(report.Items, i => i.Kind == AttentionKind.FailedWebhookDeliveries);
        var text = System.Text.Json.JsonSerializer.Serialize(item);
        Assert.DoesNotContain("secret-looking", text);
        Assert.DoesNotContain("private.example.com", text);
    }

    [Fact]
    public async Task ViewerOnly_WithholdsSettingsKindsAndNeverQueriesWebhookDeliveries()
    {
        var ct = TestContext.Current.CancellationToken;
        var interceptor = new RecordingCommandInterceptor();
        await using var scope = await AttentionTestDb.CreateAsync(ct, interceptor);
        var hook = Hook("ops-alerts");
        scope.Db.Webhooks.Add(hook);
        scope.Db.WebhookDeliveries.Add(Delivery(hook, "Failed", NowUtc.AddDays(-1), "HTTP 500"));
        await scope.Db.SaveChangesAsync(ct);
        interceptor.Commands.Clear();

        var report = await scope.CreateService(Clock).GetReportAsync(AttentionAccessFor.ViewerOnly, ct);

        Assert.DoesNotContain(report.Items, i => i.Kind == AttentionKind.FailedWebhookDeliveries);
        Assert.Contains(AttentionKind.FailedWebhookDeliveries, report.WithheldKinds);
        Assert.DoesNotContain(interceptor.Commands, c => c.Contains("WebhookDeliveries", StringComparison.Ordinal));
    }
}
