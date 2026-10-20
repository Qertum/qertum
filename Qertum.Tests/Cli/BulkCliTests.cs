using System.CommandLine;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class BulkCliTests
{
    private static readonly Guid OperationGuid = Guid.Parse("33333333-3333-3333-3333-333333333333");
    private static readonly BulkOperationId OperationId = new(OperationGuid);

    private static string Operation(string status, int items = 3, int done = 0, int failed = 0, string kind = "Revoke") =>
        $$"""{"id":"{{OperationGuid}}","kind":"{{kind}}","status":"{{status}}","itemCount":{{items}},"doneCount":{{done}},"skippedCount":0,"failedCount":{{failed}},"createdBy":"alice","filter":{"all":true},"excluded":{"not-issued":4} }""";

    private static string Preview(int items = 3) =>
        $$"""{"operation":{{Operation("Previewed", items)}},"sample":[]}""";

    /// <summary>Answers by method and path; records every call.</summary>
    private sealed class Api(Func<HttpMethod, string, (HttpStatusCode Status, string Body)> answer) : HttpMessageHandler
    {
        public List<string> Calls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var path = request.RequestUri!.PathAndQuery;
            Calls.Add($"{request.Method} {path}");
            var (status, body) = answer(request.Method, path);
            var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            response.Headers.TryAddWithoutValidation("Retry-After", "1");
            return Task.FromResult(response);
        }
    }

    private sealed class Harness
    {
        public Harness(Func<HttpMethod, string, (HttpStatusCode, string)> answer, FakeTimeProvider? clock = null)
        {
            Handler = new Api(answer);
            Client = new CertificateRequestsApiClient(new HttpClient(Handler) { BaseAddress = new Uri("https://api.test/") }, clock ?? new FakeTimeProvider());
        }

        public Api Handler { get; }
        public CertificateRequestsApiClient Client { get; }
        public StringWriter Out { get; } = new();
        public StringWriter Err { get; } = new();
    }

    private static readonly BulkSelection All = new(null, null, null, null, null, All: true);

    [Fact]
    public void TheBulkGroup_HasSixCommands()
    {
        var bulk = BulkCommands.Build(new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
            new Option<string?>("--token"), new Option<string>("--output"));
        Assert.Equal(["cancel", "execute", "list", "renew", "revoke", "show"], bulk.Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData(false, null, null, null, null, null, false)]            // empty
    [InlineData(true, null, "WebServer", null, null, null, false)]       // all + criterion
    [InlineData(true, "11111111-1111-1111-1111-111111111111", null, null, null, null, false)]
    public void ValidateSelection_RefusesAnEmptyOrContradictoryFilter(bool all, string? issuer, string? template, string? owner, int? within, string? cn, bool ok)
    {
        var selection = new BulkSelection(issuer is null ? null : Guid.Parse(issuer), template, owner, within, cn, all);
        Assert.Equal(ok, BulkCommands.ValidateSelection(selection) is null);
    }

    [Fact]
    public void ValidateSelection_AcceptsAllAlone_OrAnyCriterion()
    {
        Assert.Null(BulkCommands.ValidateSelection(All));
        Assert.Null(BulkCommands.ValidateSelection(new BulkSelection(null, "WebServer", null, null, null, false)));
        Assert.Null(BulkCommands.ValidateSelection(new BulkSelection(null, null, null, 30, null, false)));
    }

    [Fact]
    public async Task PreviewOnly_MakesOneCall_PrintsTheCountExclusionsAndTheCommandToRun_AndNeverExecutes()
    {
        var h = new Harness((_, _) => (HttpStatusCode.Created, Preview(3)));

        var exit = await BulkCommands.RunPreviewAsync(h.Client, BulkOperationKind.Revoke, All, "compromised",
            yes: false, confirmCount: null, wait: false, timeoutSeconds: 60, json: false, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Equal(["POST /v1/bulk-operations/preview"], h.Handler.Calls);
        var output = h.Out.ToString();
        Assert.Contains($"operation {OperationGuid}", output);
        Assert.Contains("items 3", output);
        Assert.Contains("excluded not-issued 4", output);
        Assert.Contains($"qca bulk execute {OperationGuid} --confirm-count 3", output);
    }

    [Fact]
    public async Task Revoke_WithoutAReason_FailsBeforeAnyCall()
    {
        var h = new Harness((_, _) => (HttpStatusCode.Created, Preview()));

        var exit = await BulkCommands.RunPreviewAsync(h.Client, BulkOperationKind.Revoke, All, reason: null,
            false, null, false, 60, false, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Empty(h.Handler.Calls);
        Assert.Contains("--reason", h.Err.ToString());
    }

    [Fact]
    public async Task Yes_WithoutConfirmCount_FailsBeforeAnyCall()
    {
        var h = new Harness((_, _) => (HttpStatusCode.Created, Preview()));

        var exit = await BulkCommands.RunPreviewAsync(h.Client, BulkOperationKind.Renew, All, null,
            yes: true, confirmCount: null, false, 60, false, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Empty(h.Handler.Calls);
        Assert.Contains("--confirm-count", h.Err.ToString());
    }

    [Fact]
    public async Task Yes_WhenThePreviewCountDiffersFromConfirmCount_ExecutesNothing()
    {
        var h = new Harness((_, _) => (HttpStatusCode.Created, Preview(3)));

        var exit = await BulkCommands.RunPreviewAsync(h.Client, BulkOperationKind.Renew, All, null,
            yes: true, confirmCount: 2, false, 60, false, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Equal(["POST /v1/bulk-operations/preview"], h.Handler.Calls);
        Assert.Contains("matches 3, not 2", h.Err.ToString());
        Assert.Contains("stays previewed", h.Err.ToString());
    }

    [Fact]
    public async Task YesWithTheRightCount_AndWait_PreviewsExecutesAndPollsToCompletion()
    {
        var h = new Harness((method, path) => path switch
        {
            "/v1/bulk-operations/preview" => (HttpStatusCode.Created, Preview(3)),
            var p when p.EndsWith("/execute") => (HttpStatusCode.Accepted, Operation("Running")),
            _ => (HttpStatusCode.OK, Operation("Completed", done: 3))
        });

        var exit = await BulkCommands.RunPreviewAsync(h.Client, BulkOperationKind.Revoke, All, "compromised",
            yes: true, confirmCount: 3, wait: true, timeoutSeconds: 60, json: false, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Equal("POST /v1/bulk-operations/preview", h.Handler.Calls[0]);
        Assert.Equal($"POST /v1/bulk-operations/{OperationGuid}/execute", h.Handler.Calls[1]);
        Assert.StartsWith($"GET /v1/bulk-operations/{OperationGuid}", h.Handler.Calls[2]);
        Assert.Contains("completed", h.Out.ToString());
    }

    [Fact]
    public async Task Execute_Wait_CompletedWithErrors_ExitsOne_AndNamesTheFailedCount()
    {
        var h = new Harness((_, path) => path.EndsWith("/execute")
            ? (HttpStatusCode.Accepted, Operation("Running"))
            : (HttpStatusCode.OK, Operation("CompletedWithErrors", done: 2, failed: 1)));

        var exit = await BulkCommands.RunExecuteAsync(h.Client, OperationId, 3, wait: true, 60, false, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Contains("1 failed", h.Out.ToString());
        Assert.Contains($"qca bulk show {OperationGuid}", h.Out.ToString());
    }

    [Fact]
    public async Task Execute_Wait_TimingOutWhileRunning_ExitsThree()
    {
        var clock = new FakeTimeProvider();
        var h = new Harness((_, path) => path.EndsWith("/execute")
            ? (HttpStatusCode.Accepted, Operation("Running"))
            : (HttpStatusCode.OK, Operation("Running", done: 1)), clock);

        var task = BulkCommands.RunExecuteAsync(h.Client, OperationId, 3, wait: true, timeoutSeconds: 3, false, h.Out, h.Err, TestContext.Current.CancellationToken);
        for (var i = 0; i < 2000 && !task.IsCompleted; i++)
        {
            clock.Advance(TimeSpan.FromMilliseconds(500));
            await Task.Delay(1, TestContext.Current.CancellationToken);
        }

        Assert.Equal(3, await task);
        Assert.Contains("still", h.Err.ToString());
    }

    [Fact]
    public async Task Json_PrintsThePreviewObject()
    {
        var h = new Harness((_, _) => (HttpStatusCode.Created, Preview(3)));

        var exit = await BulkCommands.RunPreviewAsync(h.Client, BulkOperationKind.Renew, All, null,
            false, null, false, 60, json: true, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        using var doc = JsonDocument.Parse(h.Out.ToString());
        Assert.Equal(3, doc.RootElement.GetProperty("operation").GetProperty("itemCount").GetInt32());
    }
}
