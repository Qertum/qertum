using Qertum.Services;

namespace Qertum.Tests.Webhooks;

public sealed class WebhookEventCatalogTests
{
    [Fact]
    public void EveryEventBelongsToExactlyOneFamily()
    {
        var families = Enum.GetValues<WebhookEventFamily>();

        foreach (var eventName in WellKnownWebhookEvents.All)
        {
            var owning = families.Where(f => WellKnownWebhookEvents.EventsFor(f).Contains(eventName)).ToList();
            Assert.Single(owning);
            Assert.Equal(owning[0], WellKnownWebhookEvents.FamilyOf(eventName));
        }
    }

    [Fact]
    public void FamilyEventSetsPartitionAll()
    {
        var union = Enum.GetValues<WebhookEventFamily>()
            .SelectMany(WellKnownWebhookEvents.EventsFor)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Equal(WellKnownWebhookEvents.All.OrderBy(e => e), union.OrderBy(e => e));
    }

    [Theory]
    [InlineData("Created", WebhookEventFamily.CertificateRequest)]
    [InlineData("Issued", WebhookEventFamily.CertificateRequest)]
    [InlineData("Updated", WebhookEventFamily.CertificateRequest)]
    [InlineData("Deleted", WebhookEventFamily.CertificateRequest)]
    [InlineData("SettingsUpdated", WebhookEventFamily.Settings)]
    [InlineData("RolePermissionsUpdated", WebhookEventFamily.Settings)]
    [InlineData("RolePermissionsRenamed", WebhookEventFamily.Settings)]
    [InlineData("TemplatePolicyChanged", WebhookEventFamily.Template)]
    [InlineData("IssuancePolicyPublished", WebhookEventFamily.Policy)]
    [InlineData("PrivateKeyDownloaded", WebhookEventFamily.KeyAccess)]
    [InlineData("PfxExported", WebhookEventFamily.KeyAccess)]
    [InlineData("IssuerKeyDownloaded", WebhookEventFamily.KeyAccess)]
    [InlineData("IssuerPfxExported", WebhookEventFamily.KeyAccess)]
    public void KnownEventsMapToTheirFamily(string eventName, WebhookEventFamily expected)
        => Assert.Equal(expected, WellKnownWebhookEvents.FamilyOf(eventName));

    [Fact]
    public void UnknownEventIsNotResolvable()
    {
        Assert.False(WellKnownWebhookEvents.TryGetFamily("NoSuchEvent", out _));
        Assert.Throws<ArgumentOutOfRangeException>(() => WellKnownWebhookEvents.FamilyOf("NoSuchEvent"));
    }

    [Fact]
    public void CatalogCountsAreExplicit()
    {
        Assert.Equal(8, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.CertificateRequest).Count);
        Assert.Equal(10, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Settings).Count);
        Assert.Equal(6, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Template).Count);
        Assert.Equal(6, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Policy).Count);
        Assert.Equal(4, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.KeyAccess).Count);
        Assert.Equal(9, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Issuer).Count);
        Assert.Single(WellKnownWebhookEvents.EventsFor(WebhookEventFamily.BulkOperation));
        Assert.Equal(3, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Notice).Count);
        Assert.Single(WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Audit));
        Assert.Equal(5, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Approval).Count);
        Assert.Equal(53, WellKnownWebhookEvents.All.Count);
    }
}
