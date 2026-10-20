using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Components;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class PqcMigrationPageTests
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private sealed class Stub(PqcMigrationReportResponse report) : HttpMessageHandler
    {
        public List<string> Urls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Urls.Add(request.RequestUri!.PathAndQuery);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(report, Web), Encoding.UTF8, "application/json")
            });
        }
    }

    private static PqcReportItem Item(string cn, bool assumed = false, PqcVerdictKind verdict = PqcVerdictKind.Refused) => new()
    {
        RequestId = new CertificateRequestId(Guid.NewGuid()), CommonName = cn, TemplateTypeKey = "WebServer",
        ValidToUtc = new DateTime(2027, 1, 2, 0, 0, 0, DateTimeKind.Utc), Status = CertificateRequestStatus.Issued,
        KeyAlgorithm = "RSA", AlgorithmAssumed = assumed, Verdict = verdict, Reason = "classical key", IsRenewal = true,
        Certificates = [new CertificateInventoryItem { SubjectKeyAlgorithm = "RSA", IssuerSignatureAlgorithm = "RSA-SHA256", ChainStatus = "Unknown" }]
    };

    private static PqcMigrationReportResponse Report(bool withObserved = true, int total = 2, int pageSize = 50) => new()
    {
        GeneratedAtUtc = new DateTime(2026, 9, 29, 12, 0, 0, DateTimeKind.Utc),
        CaDefaultStage = PqcStage.Warn,
        Templates =
        [
            new PqcTemplateReport
            {
                TypeKey = "WebServer", Name = "Web Server", CurrentStage = PqcStage.Warn, ProposedStage = PqcStage.Warn,
                LiveTotal = 10, Compliant = 4, ClassicalWarned = 6, AlgorithmAssumed = 1, InFlight = 2, NotAffected = 3
            }
        ],
        Items = new PagedResult<PqcReportItem>
        {
            Items = [Item("a.corp.example"), Item("b.corp.example", assumed: true)], TotalCount = total, Page = 1, PageSize = pageSize
        },
        Observed = withObserved
            ? new PqcObservedTraffic
            {
                RequestedDays = 90, EffectiveDays = 30, RetentionDays = 30, TotalEvents = 5, DistinctIdentities = 2,
                Counts = [new PqcObservedCount { TemplateTypeKey = "WebServer", Source = "acme", Kind = "Warned", Count = 5, DistinctIdentities = 2 }]
            }
            : null,
        Withheld = withObserved ? [] : ["observed"]
    };

    private static (BunitContext Context, Stub Api) NewContext(PqcMigrationReportResponse report)
    {
        var api = new Stub(report);
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.CertificatesView);
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        return (context, api);
    }

    private static IRenderedComponent<PqcMigration> Render(BunitContext context, string query = "")
    {
        context.Services.GetRequiredService<NavigationManager>().NavigateTo($"/pqc-migration{query}");
        var cut = context.Render<PqcMigration>();
        cut.WaitForElement("[data-test='report-notes']");
        return cut;
    }

    [Fact]
    public void ThePageGatesOnCertificatesView()
    {
        var attribute = Assert.Single(typeof(PqcMigration)
            .GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), inherit: true)
            .Cast<Microsoft.AspNetCore.Authorization.AuthorizeAttribute>());
        Assert.Equal(AppPermissions.CertificatesView, attribute.Policy);
        Assert.Null(attribute.Roles);
    }

    [Fact]
    public async Task ShowsTheSummary_TheItemsWithTheirSeparateFacts_AndTheSharedScopeNote()
    {
        var (context, _) = NewContext(Report());
        await using var _1 = context;

        var cut = Render(context);

        var row = cut.Find("tr[data-template='WebServer']");
        Assert.Contains("Web Server", row.TextContent);
        Assert.Contains("10", row.TextContent);
        Assert.Equal(2, cut.FindAll("tr[data-item]").Count);
        Assert.Contains("RSA-SHA256", cut.Markup);            // issuer signature is its own fact
        Assert.Contains("assumed", cut.FindAll("tr[data-item]")[1].TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(PqcMigrationReportNotes.Scope, cut.Find("[data-test='report-notes']").TextContent.Trim());
    }

    [Fact]
    public async Task NeverShowsAReadinessScore()
    {
        var (context, _) = NewContext(Report());
        await using var _1 = context;

        var markup = Render(context).Markup;

        foreach (var word in new[] { "PQC ready", "score", "% ready" })
            Assert.DoesNotContain(word, markup, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ShowsTheObservedBlock_WithTheWindowAndRetentionStated()
    {
        var (context, _) = NewContext(Report(withObserved: true));
        await using var _1 = context;

        var cut = Render(context);

        var text = cut.Find("[data-test='observed']").TextContent;
        Assert.Contains("30 of the 90 days", text);
        Assert.Contains("kept 30 days", text);
        Assert.Contains("acme", text);
        Assert.Empty(cut.FindAll("[data-test='observed-withheld']"));
    }

    [Fact]
    public async Task WhenWithheld_SaysSo_AndShowsNoZeros()
    {
        var (context, _) = NewContext(Report(withObserved: false));
        await using var _1 = context;

        var cut = Render(context);

        Assert.Contains("withheld", cut.Find("[data-test='observed-withheld']").TextContent, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(cut.FindAll("[data-test='observed']"));
    }

    [Fact]
    public async Task TheStagePicker_DefaultsToTheCurrentStage_AndAChoiceAsksForThatProposal()
    {
        var (context, api) = NewContext(Report());
        await using var _1 = context;
        var cut = Render(context);

        Assert.Equal("Warn", cut.Find("#proposed-stage").GetAttribute("value"));
        Assert.DoesNotContain(api.Urls, u => u.Contains("proposedStage=", StringComparison.Ordinal));

        cut.Find("#proposed-stage").Change("Enforce");

        cut.WaitForAssertion(() => Assert.Contains(api.Urls, u => u.Contains("proposedStage=Enforce", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task TheQueryString_PreselectsTemplateStageAndPage()
    {
        var (context, api) = NewContext(Report(total: 120, pageSize: 50));
        await using var _1 = context;

        Render(context, "?template=WebServer&proposedStage=Pilot&page=2");

        var url = Assert.Single(api.Urls);
        Assert.Contains("template=WebServer", url);
        Assert.Contains("proposedStage=Pilot", url);
        Assert.Contains("page=2", url);
    }

    [Fact]
    public async Task ManyItems_ShowThePager()
    {
        var (context, _) = NewContext(Report(total: 120, pageSize: 50));
        await using var _1 = context;

        var cut = Render(context);

        Assert.NotEmpty(cut.FindAll("[data-test='pager']"));
    }

    [Fact]
    public async Task ASettingsLoosening_OffersAPreviewOfThatStage()
    {
        await using var context = SettingsPageHarness.NewContext(admin: true, pqcStage: "Enforce");
        var cut = context.Render<Settings>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#settings-tab-issuance")));
        cut.Find("#settings-tab-issuance").Click();

        Assert.Equal("pqc-migration", cut.Find("a[data-test='preview-impact-link']").GetAttribute("href"));
        cut.Find("#pqc-stage").Change("Warn");

        Assert.Equal("pqc-migration?proposedStage=Warn", cut.Find("a[data-test='preview-impact']").GetAttribute("href"));
    }
}
