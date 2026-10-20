using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookLifecycleSiteTests
{
    private const string Actor = "alice";

    private static async Task SeedHookAsync(PolicyTestDb harness, WebhookEventFamily family, CancellationToken ct)
    {
        harness.Db.Webhooks.Add(new Webhook
        {
            Id = new WebhookId(Guid.NewGuid()),
            Name = $"hook-{family}",
            Url = "https://h.invalid/hook",
            Family = family,
            EventsJson = "[]",
            IsEnabled = true,
            CreatedAtUtc = DateTime.UtcNow,
            UpdatedAtUtc = DateTime.UtcNow
        });
        await harness.Db.SaveChangesAsync(ct);
        harness.Db.ChangeTracker.Clear();
    }

    private static async Task<List<string>> EventTypesAsync(PolicyTestDb harness, CancellationToken ct) =>
        await harness.Db.WebhookDeliveries.AsNoTracking().Select(d => d.EventType).ToListAsync(ct);

    private static CertificateTemplate NewTemplate(string name, string typeKey) => new()
    {
        Name = name,
        TypeKey = typeKey,
        Description = "created by a test",
        KeyUsagesJson = """["DigitalSignature"]""",
        ExtendedKeyUsagesJson = "[]",
        SanTypesJson = "[]"
    };

    [Fact]
    public async Task TemplateCrudEnqueuesItsEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedHookAsync(harness, WebhookEventFamily.Template, ct);

        var templates = harness.CreateTemplateService();
        var created = await templates.CreateAsync(NewTemplate("Hook Test", "HookTest"), Actor, ct);
        await templates.UpdateAsync(created.Id, NewTemplate("Hook Test 2", "HookTest"), Actor, ct);
        await templates.DeleteAsync(created.Id, Actor, ct);

        Assert.Equal(
            new[] { "TemplateCreated", "TemplateDeleted", "TemplateUpdated" },
            (await EventTypesAsync(harness, ct)).OrderBy(e => e, StringComparer.Ordinal));
    }

    [Fact]
    public async Task TemplatePolicyLinkEnqueuesTemplatePolicyChanged()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);

        var management = harness.CreateManagementService();
        var policy = await management.CreateAsync(new SaveIssuancePolicyRequest { Name = "link-policy" }, Actor, ct);
        await management.SaveDraftAsync(policy.Id, new SaveIssuancePolicyDraftRequest { MaxValidityDays = 90 }, Actor, ct);
        var draft = (await management.GetAsync(policy.Id, ct))!.Draft!;
        await management.PublishAsync(policy.Id, new PublishIssuancePolicyRequest
        {
            DraftVersionId = draft.Id,
            DraftUpdatedAtUtc = draft.UpdatedAtUtc
        }, Actor, ct);

        // Only now start listening, so the policy events above do not muddy the assertion.
        await SeedHookAsync(harness, WebhookEventFamily.Template, ct);

        var template = await harness.Db.CertificateTemplates.AsNoTracking().FirstAsync(t => t.TypeKey == "WebServer", ct);
        await harness.CreateTemplateService().SetIssuancePolicyAsync(template.Id, policy.Id, Actor, ct);

        var delivery = await harness.Db.WebhookDeliveries.AsNoTracking().SingleAsync(ct);
        Assert.Equal("TemplatePolicyChanged", delivery.EventType);
        Assert.Contains(((Guid)policy.Id).ToString(), delivery.Payload);
    }

    [Fact]
    public async Task PolicyCrudAndPublishEnqueueTheirEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedHookAsync(harness, WebhookEventFamily.Policy, ct);

        var management = harness.CreateManagementService();
        var policy = await management.CreateAsync(new SaveIssuancePolicyRequest { Name = "hook-policy" }, Actor, ct);
        await management.SaveDraftAsync(policy.Id, new SaveIssuancePolicyDraftRequest
        {
            AllowedDnsSuffixes = [".example.com"],
            MaxValidityDays = 90
        }, Actor, ct);

        var draft = (await management.GetAsync(policy.Id, ct))!.Draft!;
        await management.PublishAsync(policy.Id, new PublishIssuancePolicyRequest
        {
            DraftVersionId = draft.Id,
            DraftUpdatedAtUtc = draft.UpdatedAtUtc
        }, Actor, ct);

        var events = await EventTypesAsync(harness, ct);
        Assert.Contains("IssuancePolicyCreated", events);
        Assert.Contains("IssuancePolicyDraftSaved", events);
        Assert.Contains("IssuancePolicyPublished", events);
    }

    [Fact]
    public async Task SettingsSaveEnqueuesSettingsUpdated()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedHookAsync(harness, WebhookEventFamily.Settings, ct);

        var requests = harness.CreateRequestServiceWithWebhooks();
        var settings = await requests.GetSettingsAsync(ct);
        settings.ExpiringSoonDays = 42;
        await requests.SetupOrUpdateSettingsAsync(settings, Actor, ct);

        var delivery = await harness.Db.WebhookDeliveries.AsNoTracking().SingleAsync(ct);
        Assert.Equal("SettingsUpdated", delivery.EventType);
        Assert.Contains("\"family\":\"Settings\"", delivery.Payload);
        Assert.Contains(Actor, delivery.Payload);
    }

    [Fact]
    public async Task RequestUpdateAndDeleteEnqueueTheirEvents()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedHookAsync(harness, WebhookEventFamily.CertificateRequest, ct);

        var requests = harness.CreateRequestServiceWithWebhooks();
        var created = await requests.CreateAsync(new CertificateRequest
        {
            CommonName = "hook.example.com",
            Type = "WebServer",
            RequestedBy = Actor
        }, Actor, ct);

        created.CommonName = "hook2.example.com";
        await requests.UpdateAsync(created.Id, created, Actor, ct);
        await requests.DeleteAsync(created.Id, Actor, ct);

        var events = await EventTypesAsync(harness, ct);
        Assert.Contains("Created", events);
        Assert.Contains("Updated", events);
        Assert.Contains("Deleted", events);
    }

    [Fact]
    public async Task AFailedEnqueueDoesNotFailTheMutation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var harness = await PolicyTestDb.CreateAsync(ct);
        await SeedHookAsync(harness, WebhookEventFamily.Template, ct);

        // Break the enqueue at the database rather than with a throwing test double: the non-fatal
        // guarantee lives inside WebhookService, so this exercises the real implementation's catch.
        await harness.Db.Database.ExecuteSqlRawAsync("DROP TABLE WebhookDeliveries;", ct);

        var created = await harness.CreateTemplateService().CreateAsync(NewTemplate("Still Saved", "StillSaved"), Actor, ct);

        Assert.NotNull(await harness.Db.CertificateTemplates.SingleOrDefaultAsync(t => t.Id == created.Id, ct));
    }
}
