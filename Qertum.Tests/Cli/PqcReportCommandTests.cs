using System.CommandLine;
using System.Net;
using System.Text;
using System.Text.Json;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class PqcReportCommandTests
{
    private static Command Pqc() => PqcCommands.Build(
        new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
        new Option<string?>("--token"), new Option<string>("--output"));

    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private sealed class Pager(int total) : HttpMessageHandler
    {
        public List<string> Urls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Urls.Add(request.RequestUri!.PathAndQuery);
            var query = System.Web.HttpUtility.ParseQueryString(request.RequestUri.Query);
            var page = int.Parse(query["page"]!);
            var size = int.Parse(query["pageSize"]!);
            var items = Enumerable.Range((page - 1) * size, Math.Max(0, Math.Min(size, total - (page - 1) * size)))
                .Select(i => Item($"host{i}.corp.example")).ToList();
            var report = new PqcMigrationReportResponse
            {
                GeneratedAtUtc = new DateTime(2026, 9, 29, 0, 0, 0, DateTimeKind.Utc), CaDefaultStage = PqcStage.Warn,
                Templates = [Template()], Withheld = ["observed"],
                Items = new PagedResult<PqcReportItem> { Items = items, TotalCount = total, Page = page, PageSize = size }
            };
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(report, Web), Encoding.UTF8, "application/json")
            });
        }
    }

    private static PqcTemplateReport Template() => new()
    {
        TypeKey = "WebServer", Name = "Web Server", CurrentStage = PqcStage.Warn, ProposedStage = PqcStage.Enforce,
        LiveTotal = 10, Compliant = 4, ClassicalRefused = 5, ClassicalWarned = 1, AlgorithmAssumed = 2, InFlight = 3, NotAffected = 7
    };

    private static PqcReportItem Item(string cn, bool assumed = false) => new()
    {
        RequestId = new CertificateRequestId(Guid.NewGuid()), CommonName = cn, TemplateTypeKey = "WebServer",
        ValidToUtc = new DateTime(2027, 1, 2, 0, 0, 0, DateTimeKind.Utc), Status = CertificateRequestStatus.Issued,
        KeyAlgorithm = "RSA", AlgorithmAssumed = assumed, Verdict = PqcVerdictKind.Refused, IsRenewal = true
    };

    [Fact]
    public void TheReportCommandExists_WithItsOptions()
    {
        var report = Pqc().Subcommands.Single(c => c.Name == "report");

        Assert.Equal(["--days", "--page", "--page-size", "--proposed-stage", "--template"],
            report.Options.Select(o => o.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Options_MapToTheQuery()
    {
        var parsed = Pqc().Parse("report --template WebServer --proposed-stage warn --days 7 --page 2 --page-size 25");
        Assert.Empty(parsed.Errors);

        var (query, error) = PqcCommands.BuildReportQuery(parsed);

        Assert.Null(error);
        Assert.Equal(("WebServer", PqcStage.Warn, 7, 2, 25),
            (query!.TemplateTypeKey, query.ProposedStage, query.ObservedDays, query.Page, query.PageSize));
    }

    [Theory]
    [InlineData("report --proposed-stage sideways")]
    [InlineData("report --days 0")]
    [InlineData("report --page-size 501")]
    public void BadOptions_FailLocallyWithAReason(string args)
    {
        var (query, error) = PqcCommands.BuildReportQuery(Pqc().Parse(args));

        Assert.Null(query);
        Assert.False(string.IsNullOrWhiteSpace(error));
    }

    [Fact]
    public async Task Json_CollectsEveryPageIntoOneDocument()
    {
        var handler = new Pager(total: 1203);
        var api = new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") });

        var merged = await PqcCommands.CollectAllPagesAsync(api, new PqcReportQuery { ProposedStage = PqcStage.Enforce },
            TestContext.Current.CancellationToken);

        Assert.Equal(1203, merged.Items.Items.Count);
        Assert.Equal(1203, merged.Items.TotalCount);
        Assert.Equal(3, handler.Urls.Count);
        Assert.All(handler.Urls, u => Assert.Contains("pageSize=500", u));
        Assert.All(handler.Urls, u => Assert.Contains("proposedStage=Enforce", u));
        Assert.Equal(["observed"], merged.Withheld);
    }

    [Fact]
    public void TheTable_ShowsSummaryItemsAssumedFlagAndTheSharedScopeNote()
    {
        var report = new PqcMigrationReportResponse
        {
            CaDefaultStage = PqcStage.Warn, ProposedStage = PqcStage.Enforce, Templates = [Template()],
            Withheld = ["observed"],
            Items = new PagedResult<PqcReportItem> { Items = [Item("a.corp.example"), Item("b.corp.example", assumed: true)], TotalCount = 2, Page = 1, PageSize = 50 }
        };

        var text = string.Join('\n', PqcCommands.ReportLines(report));

        Assert.Contains("Web Server", text);
        Assert.Contains("Warn -> Enforce", text);
        Assert.Contains("a.corp.example", text);
        Assert.Contains("assumed", text);
        Assert.Contains("observed: withheld", text);
        Assert.EndsWith(PqcMigrationReportNotes.Scope, text.TrimEnd());
        Assert.DoesNotContain("ready", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheTable_SaysWhenNothingIsAtStake()
    {
        var report = new PqcMigrationReportResponse { Templates = [], Items = new PagedResult<PqcReportItem>() };

        Assert.Contains("No classical certificates", string.Join('\n', PqcCommands.ReportLines(report)));
    }
}
