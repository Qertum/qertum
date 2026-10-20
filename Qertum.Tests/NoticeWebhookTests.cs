using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests;

public sealed class NoticeWebhookTests
{
    [Theory]
    [InlineData("CertificateExpiring")]
    [InlineData("RenewalStalled")]
    [InlineData("RenewalFailed")]
    public void EachNoticeEvent_BelongsToTheNoticeFamily(string eventType)
    {
        Assert.Contains(eventType, WellKnownWebhookEvents.All);
        Assert.Contains(eventType, WellKnownWebhookEvents.EventsFor(WebhookEventFamily.Notice));
        Assert.Equal(WebhookEventFamily.Notice, WellKnownWebhookEvents.FamilyOf(eventType));
    }

    [Fact]
    public void TheNoticeFamily_CarriesTheContactEmail_AndNoOtherFamilyDoes()
    {
        Assert.Contains("contactEmail", WebhookEventFields.All(WebhookEventFamily.Notice));
        foreach (var family in Enum.GetValues<WebhookEventFamily>().Where(f => f != WebhookEventFamily.Notice))
            Assert.DoesNotContain("contactEmail", WebhookEventFields.All(family));
    }

    [Fact]
    public void TheNoticeFamily_AllowsExactlyTheSpecifiedFields()
    {
        var expected = new[]
        {
            "commonName", "validTo", "daysLeft", "level", "renewalId", "failureReason",
            "ownerTeam", "contactEmail", "targetSystem", "ticketReference"
        };

        Assert.Equal(expected.Order(StringComparer.Ordinal), WebhookEventFields.For(WebhookEventFamily.Notice).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void TheContactEmail_IsAValidPlaceholderOnlyInTheNoticeFamily()
    {
        Assert.True(WebhookEventFields.IsKnown(WebhookEventFamily.Notice, "contactEmail"));
        Assert.False(WebhookEventFields.IsKnown(WebhookEventFamily.CertificateRequest, "contactEmail"));
    }

    [Fact]
    public void NoticeRaised_IsMappedToTheCertificateRequest() =>
        Assert.Equal(LifecycleSubjectTypes.CertificateRequest, AuditActionSubjects.SubjectTypeOf("NoticeRaised"));
}
