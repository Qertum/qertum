using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookEnqueueTests
{
    private static async Task<WebhookId> SeedAsync(
        PolicyTestDb harness, WebhookEventFamily family, string eventsJson, string url,
        bool isEnabled = true, CancellationToken ct = default)
    {
        var id = new WebhookId(Guid.NewGuid());
        harness.Db.Webhooks.Add(new Webhook
        {
            Id = id, Name = $"hook-{family}", Url = url, Family = family,
            EventsJson = eventsJson, IsEnabled = isEnabled,
            CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
        });
        await harness.Db.SaveChangesAsync(ct);
        harness.Db.ChangeTracker.Clear();
        return id;
    }

    private static WebhookService Service(PolicyTestDb harness) =>
        new(harness.Db, NullLogger<WebhookService>.Instance);

    [Fact]
    public async Task EmptyEventsJsonSubscribesToTheWholeFamily()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.Template, "[]", "https://h.invalid/t", ct: ct);

        await Service(harness).EnqueueEventAsync(
            new WebhookEvent(WellKnownWebhookEvents.TemplateDeleted, Guid.NewGuid(), "WebServer"), ct);

        var delivery = await harness.Db.WebhookDeliveries.SingleAsync(ct);
        Assert.Equal("TemplateDeleted", delivery.EventType);
    }

    [Fact]
    public async Task EventsJsonNarrowsWithinTheFamily()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.Template, """["TemplateDeleted"]""", "https://h.invalid/t", ct: ct);

        var service = Service(harness);
        await service.EnqueueEventAsync(new WebhookEvent(WellKnownWebhookEvents.TemplateCreated, Guid.NewGuid(), "A"), ct);
        Assert.Empty(await harness.Db.WebhookDeliveries.ToListAsync(ct));

        await service.EnqueueEventAsync(new WebhookEvent(WellKnownWebhookEvents.TemplateDeleted, Guid.NewGuid(), "A"), ct);
        Assert.Single(await harness.Db.WebhookDeliveries.ToListAsync(ct));
    }

    [Fact]
    public async Task AWebhookNeverReceivesAnotherFamilysEvent()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.Template, "[]", "https://h.invalid/t", ct: ct);

        await Service(harness).EnqueueEventAsync(
            new WebhookEvent(WellKnownWebhookEvents.Issued, Guid.NewGuid(), "cert.example.com"), ct);

        Assert.Empty(await harness.Db.WebhookDeliveries.ToListAsync(ct));
    }

    [Fact]
    public async Task DisabledWebhookReceivesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.Policy, "[]", "https://h.invalid/p", isEnabled: false, ct: ct);

        await Service(harness).EnqueueEventAsync(
            new WebhookEvent(WellKnownWebhookEvents.IssuancePolicyPublished, Guid.NewGuid(), "strict"), ct);

        Assert.Empty(await harness.Db.WebhookDeliveries.ToListAsync(ct));
    }

    [Fact]
    public async Task BodyCarriesFamilyPerformedByAndTheFamilyData()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.Policy, "[]", "https://h.invalid/p", ct: ct);

        await Service(harness).EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.IssuancePolicyPublished,
            Guid.NewGuid(),
            "strict",
            PerformedBy: "alice",
            Fields: new Dictionary<string, string?>
            {
                ["policyName"] = "strict",
                ["versionNumber"] = "3",
                ["versionStatus"] = "Published"
            }), ct);

        var delivery = await harness.Db.WebhookDeliveries.SingleAsync(ct);
        using var doc = JsonDocument.Parse(delivery.Payload);
        var root = doc.RootElement;

        Assert.Equal("IssuancePolicyPublished", root.GetProperty("event").GetString());
        Assert.Equal("Policy", root.GetProperty("family").GetString());
        Assert.Equal("alice", root.GetProperty("performedBy").GetString());
        Assert.Equal("strict", root.GetProperty("data").GetProperty("policyName").GetString());
        Assert.Equal("3", root.GetProperty("data").GetProperty("versionNumber").GetString());
    }

    [Fact]
    public async Task FieldsOutsideTheAllowlistAreDropped()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.Template, "[]", "https://h.invalid/t", ct: ct);

        await Service(harness).EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.TemplateUpdated, Guid.NewGuid(), "WebServer",
            Fields: new Dictionary<string, string?>
            {
                ["templateName"] = "WebServer",
                ["privateKeyPem"] = "-----BEGIN PRIVATE KEY-----",
                ["commonName"] = "belongs-to-another-family"
            }), ct);

        var delivery = await harness.Db.WebhookDeliveries.SingleAsync(ct);
        Assert.Contains("WebServer", delivery.Payload);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", delivery.Payload);
        Assert.DoesNotContain("belongs-to-another-family", delivery.Payload);
    }

    [Fact]
    public async Task KeyAccessSuppressesTheResourceIdentity()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.KeyAccess, "[]", "https://h.invalid/k?t={publicKeyThumbprint}", ct: ct);

        await Service(harness).EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.PrivateKeyDownloaded,
            Guid.NewGuid(),
            "secret.example.com",
            PerformedBy: "bob",
            Fields: new Dictionary<string, string?> { ["publicKeyThumbprint"] = "abc123" }), ct);

        var delivery = await harness.Db.WebhookDeliveries.SingleAsync(ct);

        Assert.Null(delivery.ResourceId);
        Assert.Null(delivery.ResourceName);
        Assert.DoesNotContain("secret.example.com", delivery.Payload);
        Assert.Contains("abc123", delivery.Payload);
        Assert.Equal("https://h.invalid/k?t=abc123", delivery.ResolvedUrl);

        using var doc = JsonDocument.Parse(delivery.Payload);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("resourceId").ValueKind);
        Assert.Equal(JsonValueKind.Null, doc.RootElement.GetProperty("resourceName").ValueKind);
        Assert.Equal("bob", doc.RootElement.GetProperty("performedBy").GetString());
    }

    [Fact]
    public async Task ResolvedUrlIsRecordedPerWebhook()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.CertificateRequest, "[]",
            "https://a.invalid/hook?e={event}&cn={commonName}", ct: ct);
        await SeedAsync(harness, WebhookEventFamily.CertificateRequest, "[]", "https://b.invalid/plain", ct: ct);

        await Service(harness).EnqueueEventAsync(new WebhookEvent(
            WellKnownWebhookEvents.Issued, Guid.NewGuid(), "web.example.com",
            Fields: new Dictionary<string, string?> { ["commonName"] = "web.example.com" }), ct);

        var resolved = await harness.Db.WebhookDeliveries
            .Select(d => d.ResolvedUrl).OrderBy(u => u).ToListAsync(ct);

        Assert.Equal(
            new[] { "https://a.invalid/hook?e=Issued&cn=web.example.com", "https://b.invalid/plain" },
            resolved);
    }

    [Fact]
    public async Task AnUnknownEventNameEnqueuesNothingAndDoesNotThrow()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedAsync(harness, WebhookEventFamily.CertificateRequest, "[]", "https://h.invalid/c", ct: ct);

        await Service(harness).EnqueueEventAsync(new WebhookEvent("NotAnEvent", Guid.NewGuid(), "x"), ct);

        Assert.Empty(await harness.Db.WebhookDeliveries.ToListAsync(ct));
    }
}
