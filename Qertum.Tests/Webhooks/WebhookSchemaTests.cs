using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookSchemaTests
{
    [Fact]
    public async Task FamilyRoundTripsAsAString()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);

        harness.Db.Webhooks.Add(new Webhook
        {
            Id = Guid.NewGuid(),
            Name = "policy-hook",
            Url = "https://hook.invalid/p",
            Family = WebhookEventFamily.Policy,
            EventsJson = "[]",
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        });
        await harness.Db.SaveChangesAsync(ct);
        harness.Db.ChangeTracker.Clear();

        var stored = await harness.Db.Webhooks.SingleAsync(ct);
        Assert.Equal(WebhookEventFamily.Policy, stored.Family);

        var raw = await harness.Db.Database
            .SqlQuery<string>($"SELECT Family AS Value FROM Webhooks")
            .SingleAsync(ct);
        Assert.Equal("Policy", raw);
    }

    [Fact]
    public void FamilyDefaultsToCertificateRequest()
        => Assert.Equal(WebhookEventFamily.CertificateRequest, new Webhook().Family);

    [Fact]
    public async Task ResolvedUrlIsOptional()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);

        var webhookId = new WebhookId(Guid.NewGuid());
        harness.Db.Webhooks.Add(new Webhook
        {
            Id = webhookId, Name = "h", Url = "https://hook.invalid/h",
            EventsJson = "[]", CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
        });
        harness.Db.WebhookDeliveries.Add(new WebhookDelivery
        {
            Id = Guid.NewGuid(), WebhookId = webhookId, EventType = "Issued",
            Payload = "{}", Status = "Pending", NextAttemptAfterUtc = DateTime.UtcNow,
            CreatedAtUtc = DateTime.UtcNow, ResolvedUrl = null
        });
        await harness.Db.SaveChangesAsync(ct);
        harness.Db.ChangeTracker.Clear();

        var stored = await harness.Db.WebhookDeliveries.SingleAsync(ct);
        Assert.Null(stored.ResolvedUrl);
    }
}
