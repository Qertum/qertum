using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

public sealed class CertificateTimelineComponentTests
{
    private static readonly Guid RequestId = Guid.NewGuid();
    private static readonly Guid PreviousId = Guid.NewGuid();

    [Fact]
    public async Task RendersEntriesOldestFirstWithRecordMilestonesMarked()
    {
        await using var context = NewContext(new CertificateTimelineResponse
        {
            Subject = Summary(RequestId, "web.example.com"),
            Entries =
            [
                new() { OccurredAtUtc = new DateTime(2026, 9, 1, 8, 0, 0, DateTimeKind.Utc), Kind = TimelineEntryKind.Audit, Action = "Created", PerformedBy = "alice" },
                new() { OccurredAtUtc = new DateTime(2026, 9, 1, 9, 0, 0, DateTimeKind.Utc), Kind = TimelineEntryKind.Record, Action = "Issued" },
            ],
            Completeness = TimelineCompleteness.Full
        });

        var cut = context.Render<CertificateTimeline>(p => p.Add(x => x.RequestId, RequestId));

        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("[data-test='timeline-entry']").Count));
        var entries = cut.FindAll("[data-test='timeline-entry']");
        Assert.Contains("Created", entries[0].TextContent);
        Assert.Contains("from the certificate record", entries[1].TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(cut.FindAll("[data-test='timeline-partial']"));
    }

    [Fact]
    public async Task WithheldSectionsAndPartialHistory_AreSaidOutLoud()
    {
        await using var context = NewContext(new CertificateTimelineResponse
        {
            Subject = Summary(RequestId, "web.example.com"),
            Withheld = [new() { Section = TimelineSection.KeyExports, Count = 2 }, new() { Section = TimelineSection.WebhookDeliveries, Count = 0 }],
            Completeness = TimelineCompleteness.PartialBeforeUpgrade
        });

        var cut = context.Render<CertificateTimeline>(p => p.Add(x => x.RequestId, RequestId));

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='timeline-withheld']")));
        var withheld = cut.Find("[data-test='timeline-withheld']").TextContent;
        Assert.Contains("2 key export", withheld);
        Assert.Contains("webhook deliveries", withheld, StringComparison.OrdinalIgnoreCase);
        Assert.NotEmpty(cut.FindAll("[data-test='timeline-partial']"));
    }

    [Fact]
    public async Task ARenewalEntry_ShowsBothCertificatesSideBySide()
    {
        await using var context = NewContext(new CertificateTimelineResponse
        {
            Subject = Summary(RequestId, "web.example.com", serial: "BB"),
            Entries = [new() { OccurredAtUtc = DateTime.UtcNow, Kind = TimelineEntryKind.Renewal, Action = "RenewedFrom", RelatedRequestId = PreviousId }],
            Related = [Summary(PreviousId, "web.example.com", serial: "AA")],
        });

        var cut = context.Render<CertificateTimeline>(p => p.Add(x => x.RequestId, RequestId));

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='timeline-renewal-compare']")));
        var compare = cut.Find("[data-test='timeline-renewal-compare']").TextContent;
        Assert.Contains("AA", compare);
        Assert.Contains("BB", compare);
    }

    [Fact]
    public async Task AFailedLoad_SaysUnavailableRatherThanShowingAnEmptyHistory()
    {
        await using var context = NewContext(response: null);

        var cut = context.Render<CertificateTimeline>(p => p.Add(x => x.RequestId, RequestId));

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='timeline-unavailable']")));
        Assert.Empty(cut.FindAll("[data-test='timeline-entry']"));
    }

    private static TimelineCertificateSummary Summary(Guid id, string cn, string? serial = null) => new()
    {
        Id = id, CommonName = cn, Status = CertificateRequestStatus.Issued, SerialNumber = serial,
        ValidFrom = new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc), ValidTo = new DateTime(2026, 12, 1, 0, 0, 0, DateTimeKind.Utc)
    };

    private static BunitContext NewContext(CertificateTimelineResponse? response)
    {
        var context = new BunitContext();
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new TimelineStub(response)) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    private sealed class TimelineStub(CertificateTimelineResponse? response) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(response is null
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
                : new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonSerializer.Serialize(response, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
                });
    }
}
