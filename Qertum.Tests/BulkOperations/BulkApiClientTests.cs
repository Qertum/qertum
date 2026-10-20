using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;

namespace Qertum.Tests.BulkOperations;

/// <summary>The bulk operation calls on the typed client, and its poller (same Retry-After rules as WaitForFinalAsync).</summary>
public sealed class BulkApiClientTests
{
    private static readonly BulkOperationId Id = new(Guid.Parse("22222222-2222-2222-2222-222222222222"));

    private sealed record Step(HttpStatusCode Status, string Body, string? RetryAfter = null, string? CorrelationId = null);

    private sealed class Script(params Step[] steps) : HttpMessageHandler
    {
        private int _next;
        public int Calls => Volatile.Read(ref _next);
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.Method, request.RequestUri!.PathAndQuery,
                request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken)));
            var step = steps[Math.Min(Interlocked.Increment(ref _next) - 1, steps.Length - 1)];
            var response = new HttpResponseMessage(step.Status) { Content = new StringContent(step.Body, Encoding.UTF8, "application/json") };
            if (step.RetryAfter is not null) response.Headers.TryAddWithoutValidation("Retry-After", step.RetryAfter);
            if (step.CorrelationId is not null) response.Headers.Add("X-Correlation-Id", step.CorrelationId);
            return response;
        }
    }

    private static string Operation(string status, int done = 0) =>
        $$"""{"id":"{{(Guid)Id}}","kind":"Revoke","status":"{{status}}","itemCount":3,"doneCount":{{done}},"skippedCount":0,"failedCount":0,"createdBy":"alice","filter":{"all":true},"excluded":{} }""";

    private static Step Ok(string status, int done = 0, string? retryAfter = null) => new(HttpStatusCode.OK, Operation(status, done), retryAfter);

    private static CertificateRequestsApiClient Client(Script script, FakeTimeProvider? clock = null) =>
        new(new HttpClient(script) { BaseAddress = new Uri("http://api.test/") }, clock ?? new FakeTimeProvider());

    private static async Task<T> Drive<T>(Task<T> task, FakeTimeProvider clock)
    {
        for (var i = 0; i < 2000 && !task.IsCompleted; i++)
        {
            clock.Advance(TimeSpan.FromMilliseconds(500));
            await Task.Delay(1, TestContext.Current.CancellationToken);
        }
        return await task;
    }

    [Fact]
    public async Task Preview_PostsKindFilterAndReason_AndReadsThePreview()
    {
        var script = new Script(new Step(HttpStatusCode.Created,
            $$"""{"operation":{{Operation("Previewed")}},"sample":[{"requestId":"{{Guid.NewGuid()}}","commonName":"a.example","outcome":"Pending"}]}"""));

        var preview = await Client(script).PreviewBulkOperationAsync(
            new(BulkOperationKind.Revoke, new BulkOperationFilter { All = true }, "compromised"), TestContext.Current.CancellationToken);

        var (method, path, body) = Assert.Single(script.Requests);
        Assert.Equal(HttpMethod.Post, method);
        Assert.Equal("/v1/bulk-operations/preview", path);
        using var json = JsonDocument.Parse(body!);
        Assert.Equal("Revoke", json.RootElement.GetProperty("kind").GetString());
        Assert.True(json.RootElement.GetProperty("filter").GetProperty("all").GetBoolean());
        Assert.Equal("compromised", json.RootElement.GetProperty("reason").GetString());
        Assert.Equal(BulkOperationStatus.Previewed, preview.Operation.Status);
        Assert.Equal("a.example", Assert.Single(preview.Sample).CommonName);
    }

    [Fact]
    public async Task Execute_PostsTheConfirmCount()
    {
        var script = new Script(new Step(HttpStatusCode.Accepted, Operation("Running")));

        var view = await Client(script).ExecuteBulkOperationAsync(Id, 3, TestContext.Current.CancellationToken);

        var (_, path, body) = Assert.Single(script.Requests);
        Assert.Equal($"/v1/bulk-operations/{Id}/execute", path);
        Assert.Equal("""{"confirmCount":3}""", body);
        Assert.Equal(BulkOperationStatus.Running, view.Status);
    }

    [Fact]
    public async Task Get_Returns404AsNull()
    {
        var script = new Script(new Step(HttpStatusCode.NotFound, "{}"));
        Assert.Null(await Client(script).GetBulkOperationAsync(Id, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Items_AsksForTheOutcomeAndPage()
    {
        var script = new Script(new Step(HttpStatusCode.OK, """{"items":[],"totalCount":0,"page":2,"pageSize":50}"""));

        await Client(script).GetBulkOperationItemsAsync(Id, BulkItemOutcome.Failed, 2, 50, TestContext.Current.CancellationToken);

        Assert.Equal($"/v1/bulk-operations/{Id}/items?outcome=Failed&page=2&pageSize=50", script.Requests.Single().Path);
    }

    [Fact]
    public async Task Wait_PollsUntilAFinalStatus_ReportingEveryState()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(Ok("Running", 0, "1"), Ok("Running", 2, "1"), Ok("Completed", 3));
        var seen = new List<int>();

        var result = await Drive(Client(script, clock).WaitForBulkOperationAsync(Id, TimeSpan.FromSeconds(60),
            o => { seen.Add(o.DoneCount); return Task.CompletedTask; }, TestContext.Current.CancellationToken), clock);

        Assert.Equal(BulkWaitOutcome.Final, result.Outcome);
        Assert.Equal(BulkOperationStatus.Completed, result.Operation!.Status);
        Assert.Equal([0, 2, 3], seen);
        Assert.Equal(3, script.Calls);
    }

    [Theory]
    [InlineData("Completed")]
    [InlineData("CompletedWithErrors")]
    [InlineData("Cancelled")]
    [InlineData("Expired")]
    public async Task Wait_TreatsEveryNonPreviewedNonRunningStatusAsFinal(string status)
    {
        var script = new Script(Ok(status));
        var result = await Client(script).WaitForBulkOperationAsync(Id, TimeSpan.FromSeconds(5), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(BulkWaitOutcome.Final, result.Outcome);
        Assert.Equal(1, script.Calls);
    }

    [Theory]
    [InlineData("30", 10)]  // clamped down
    [InlineData("0", 1)]    // clamped up
    [InlineData(null, 2)]   // default
    public async Task Wait_HonoursRetryAfter_ClampedToOneToTenSeconds(string? retryAfter, int expectedSeconds)
    {
        var clock = new FakeTimeProvider();
        var script = new Script(Ok("Running", 0, retryAfter), Ok("Completed", 3));
        var task = Client(script, clock).WaitForBulkOperationAsync(Id, TimeSpan.FromMinutes(5), cancellationToken: TestContext.Current.CancellationToken);

        for (var i = 0; i < 400 && script.Calls < 1; i++) await Task.Delay(5, TestContext.Current.CancellationToken);
        clock.Advance(TimeSpan.FromSeconds(expectedSeconds) - TimeSpan.FromMilliseconds(100));
        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.Equal(1, script.Calls);

        clock.Advance(TimeSpan.FromMilliseconds(100));
        Assert.Equal(BulkWaitOutcome.Final, (await task).Outcome);
        Assert.Equal(2, script.Calls);
    }

    [Fact]
    public async Task Wait_StillPreviewed_KeepsPollingUntilTheTimeout_AndReturnsTheLastState()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(Ok("Previewed", 0, "1"));

        var result = await Drive(Client(script, clock).WaitForBulkOperationAsync(Id, TimeSpan.FromSeconds(5),
            cancellationToken: TestContext.Current.CancellationToken), clock);

        Assert.Equal(BulkWaitOutcome.TimedOut, result.Outcome);
        Assert.Equal(BulkOperationStatus.Previewed, result.Operation!.Status);
    }

    [Fact]
    public async Task Wait_ReturnsNotFoundOn404()
    {
        var script = new Script(new Step(HttpStatusCode.NotFound, "{}"));
        var result = await Client(script).WaitForBulkOperationAsync(Id, TimeSpan.FromSeconds(5), cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(BulkWaitOutcome.NotFound, result.Outcome);
        Assert.Null(result.Operation);
    }

    [Fact]
    public async Task AFailedCall_ThrowsTheProblem_WithItsCorrelationId()
    {
        var script = new Script(new Step(HttpStatusCode.Conflict,
            """{"title":"Conflict","detail":"confirmCount 1 does not match the 3 items previewed."}""", CorrelationId: "abc123"));

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() =>
            Client(script).ExecuteBulkOperationAsync(Id, 1, TestContext.Current.CancellationToken));

        Assert.Equal(HttpStatusCode.Conflict, ex.StatusCode);
        Assert.Contains("does not match", ex.Detail);
        Assert.Equal("abc123", ex.CorrelationId);
    }
}
