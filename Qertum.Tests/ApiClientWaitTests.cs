using System.Net;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;

namespace Qertum.Tests;

/// <summary>
/// <c>WaitForFinalAsync</c> polls a request until it reaches a final state, waits as long as the server's
/// <c>Retry-After</c> says (clamped to 1 to 10 seconds, 2 without a usable hint), and gives up at the timeout.
/// Time is a <see cref="FakeTimeProvider"/>: nothing here really sleeps.
/// </summary>
public sealed class ApiClientWaitTests
{
    private static readonly CertificateRequestId Id = new(Guid.Parse("11111111-1111-1111-1111-111111111111"));

    private sealed record Step(HttpStatusCode Status, string Body, string? RetryAfter);

    private sealed class Script(params Step[] steps) : HttpMessageHandler
    {
        private int _next;
        public int Calls => Volatile.Read(ref _next);
        public Exception? Throw { get; init; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (Throw is not null) throw Throw;
            var index = Math.Min(Interlocked.Increment(ref _next) - 1, steps.Length - 1);
            var step = steps[index];
            var response = new HttpResponseMessage(step.Status) { Content = new StringContent(step.Body, Encoding.UTF8, "application/json") };
            if (step.RetryAfter is not null) response.Headers.TryAddWithoutValidation("Retry-After", step.RetryAfter);
            return Task.FromResult(response);
        }
    }

    private static string Request(string status, string? failure = null) =>
        $$"""{"id":"{{(Guid)Id}}","commonName":"wait.example.com","status":"{{status}}"{{(failure is null ? "" : $",\"failureReason\":\"{failure}\"")}}}""";

    private static Step InProgress(string status = "Approved", string? retryAfter = "1") => new(HttpStatusCode.OK, Request(status), retryAfter);

    private static Step Final(string status = "Issued", string? failure = null) => new(HttpStatusCode.OK, Request(status, failure), null);

    private static CertificateRequestsApiClient Client(Script script, FakeTimeProvider clock) =>
        new(new HttpClient(script) { BaseAddress = new Uri("http://api.test/") }, clock);

    private static async Task Until(Func<bool> condition)
    {
        for (var i = 0; i < 400 && !condition(); i++)
            await Task.Delay(5, TestContext.Current.CancellationToken);
        Assert.True(condition(), "the condition did not become true in time");
    }

    /// <summary>Advances fake time in small steps until the task finishes.</summary>
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
    public async Task PollsUntilTheRequestIsFinal_AndReportsEveryStateItSaw()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(InProgress("Approved"), InProgress("Processing"), Final("Issued"));
        var seen = new List<CertificateRequestStatus>();

        var result = await Drive(Client(script, clock).WaitForFinalAsync(Id, TimeSpan.FromSeconds(60),
            r => { seen.Add(r.Status); return Task.CompletedTask; }, TestContext.Current.CancellationToken), clock);

        Assert.Equal(WaitOutcome.Final, result.Outcome);
        Assert.Equal(CertificateRequestStatus.Issued, result.Request!.Status);
        Assert.Equal(3, script.Calls);
        Assert.Equal([CertificateRequestStatus.Approved, CertificateRequestStatus.Processing, CertificateRequestStatus.Issued], seen);
    }

    [Theory]
    [InlineData("1", 1)]
    [InlineData("5", 5)]
    [InlineData("0", 1)]     // clamped up to one second
    [InlineData("999", 10)]  // clamped down to ten seconds
    [InlineData(null, 2)]    // no hint: two seconds
    [InlineData("soon", 2)]  // unusable hint: two seconds
    public async Task WaitsAsLongAsTheServerHints_ClampedToOneToTenSeconds(string? retryAfter, int expectedSeconds)
    {
        var clock = new FakeTimeProvider();
        var script = new Script(InProgress("Approved", retryAfter), Final());
        var task = Client(script, clock).WaitForFinalAsync(Id, TimeSpan.FromMinutes(5), cancellationToken: TestContext.Current.CancellationToken);

        await Until(() => script.Calls == 1);
        clock.Advance(TimeSpan.FromSeconds(expectedSeconds) - TimeSpan.FromMilliseconds(100));
        await Task.Delay(50, TestContext.Current.CancellationToken);
        Assert.Equal(1, script.Calls);            // not yet

        clock.Advance(TimeSpan.FromMilliseconds(100));
        var result = await task;

        Assert.Equal(2, script.Calls);
        Assert.Equal(WaitOutcome.Final, result.Outcome);
    }

    [Fact]
    public async Task ARequestAlreadyFinal_IsReturnedAtOnce_WithoutWaiting()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(Final("Issued"));

        var result = await Client(script, clock).WaitForFinalAsync(Id, TimeSpan.FromSeconds(30), cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(WaitOutcome.Final, result.Outcome);
        Assert.Equal(1, script.Calls);
    }

    [Fact]
    public async Task ARejectedRequest_IsFinal_AndKeepsItsFailureReason()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(InProgress("Processing"), Final("Rejected", failure: "signing failed"));

        var result = await Drive(Client(script, clock).WaitForFinalAsync(Id, TimeSpan.FromSeconds(60), cancellationToken: TestContext.Current.CancellationToken), clock);

        Assert.Equal(WaitOutcome.Final, result.Outcome);
        Assert.Equal("signing failed", result.Request!.FailureReason);
    }

    [Fact]
    public async Task TimesOut_WhileStillInProgress_AndReturnsTheLastStateSeen()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(InProgress("Approved"));

        var result = await Drive(Client(script, clock).WaitForFinalAsync(Id, TimeSpan.FromSeconds(5), cancellationToken: TestContext.Current.CancellationToken), clock);

        Assert.Equal(WaitOutcome.TimedOut, result.Outcome);
        Assert.Equal(CertificateRequestStatus.Approved, result.Request!.Status);
        Assert.True(script.Calls >= 2);
    }

    [Fact]
    public async Task ARequestThatDoesNotExist_IsNotFound_AndNeverReportedAsAnUpdate()
    {
        var clock = new FakeTimeProvider();
        var updates = 0;

        var result = await Client(new Script(new Step(HttpStatusCode.NotFound, "{}", null)), clock)
            .WaitForFinalAsync(Id, TimeSpan.FromSeconds(30), _ => { updates++; return Task.CompletedTask; }, TestContext.Current.CancellationToken);

        Assert.Equal(WaitOutcome.NotFound, result.Outcome);
        Assert.Null(result.Request);
        Assert.Equal(0, updates);
    }

    [Fact]
    public async Task AFailedCall_Propagates_NotSwallowedAsATimeout()
    {
        var clock = new FakeTimeProvider();
        var problem = new Step(HttpStatusCode.InternalServerError, """{"title":"Internal Server Error","detail":"boom"}""", null);

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() =>
            Client(new Script(problem), clock).WaitForFinalAsync(Id, TimeSpan.FromSeconds(30), cancellationToken: TestContext.Current.CancellationToken));

        Assert.Equal("boom", ex.Message);
    }

    [Fact]
    public async Task ATransportError_Propagates()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(InProgress()) { Throw = new HttpRequestException(HttpRequestError.ConnectionError, "refused") };

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            Client(script, clock).WaitForFinalAsync(Id, TimeSpan.FromSeconds(30), cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TheCallersCancellation_Cancels_ItIsNotATimeout()
    {
        var clock = new FakeTimeProvider();
        var script = new Script(InProgress());
        using var cts = new CancellationTokenSource();
        var task = Client(script, clock).WaitForFinalAsync(Id, TimeSpan.FromMinutes(5), cancellationToken: cts.Token);

        await Until(() => script.Calls == 1);
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
    }
}
