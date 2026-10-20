using System.CommandLine;
using System.Net;
using System.Text;
using Microsoft.Extensions.Time.Testing;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

/// <summary>
/// <c>qca requests approve --wait</c>: after approving, wait for issuance. Exit 0 issued, 1 rejected or a failed
/// call, 3 timed out while still on its way, so a script can tell "issued" from "failed" from "still waiting".
/// </summary>
public sealed class ApprovalWaitTests
{
    private static readonly Guid RequestGuid = Guid.Parse("22222222-2222-2222-2222-222222222222");

    private sealed class Script(params (HttpStatusCode Status, string Body)[] steps) : HttpMessageHandler
    {
        private int _next;
        public int Calls => Volatile.Read(ref _next);

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var step = steps[Math.Min(Interlocked.Increment(ref _next) - 1, steps.Length - 1)];
            var response = new HttpResponseMessage(step.Status) { Content = new StringContent(step.Body, Encoding.UTF8, "application/json") };
            response.Headers.TryAddWithoutValidation("Retry-After", "1");
            return Task.FromResult(response);
        }
    }

    private static string Body(string status, string? failure = null) =>
        $$"""{"id":"{{RequestGuid}}","commonName":"cli.example.com","status":"{{status}}"{{(failure is null ? "" : $",\"failureReason\":\"{failure}\"")}}}""";

    private static (HttpStatusCode, string) Ok(string status, string? failure = null) => (HttpStatusCode.OK, Body(status, failure));

    private static CertificateRequest Approved() => new() { Id = RequestGuid, CommonName = "cli.example.com", Status = CertificateRequestStatus.Approved };

    private static async Task<(int Exit, string Out, string Err)> Run(Script script, int timeoutSeconds = 60, CertificateRequest? approved = null)
    {
        var clock = new FakeTimeProvider();
        var client = new CertificateRequestsApiClient(new HttpClient(script) { BaseAddress = new Uri("http://api.test/") }, clock);
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();

        var task = ApprovalWait.RunAsync(client, approved ?? Approved(), TimeSpan.FromSeconds(timeoutSeconds), stdout, stderr, TestContext.Current.CancellationToken);
        for (var i = 0; i < 4000 && !task.IsCompleted; i++)
        {
            clock.Advance(TimeSpan.FromMilliseconds(500));
            await Task.Delay(1, TestContext.Current.CancellationToken);
        }

        var exit = await task;
        return (exit, stdout.ToString(), stderr.ToString());
    }

    [Fact]
    public async Task WhenTheRequestIsIssued_ItExits0_PrintsIssued_AndReportsProgressOnStderr()
    {
        var (exit, output, error) = await Run(new Script(Ok("Approved"), Ok("Processing"), Ok("Issued")));

        Assert.Equal(0, exit);
        Assert.Contains($"issued    {RequestGuid}", output, StringComparison.Ordinal);
        Assert.Contains("waiting for issuance", error, StringComparison.Ordinal);
        Assert.Contains("Processing", error, StringComparison.Ordinal);
        Assert.DoesNotContain($"issued    {RequestGuid}", error, StringComparison.Ordinal); // the result goes to stdout only
    }

    [Fact]
    public async Task EachStatusIsReportedOnce_NotOnEveryPoll()
    {
        var (_, _, error) = await Run(new Script(Ok("Approved"), Ok("Approved"), Ok("Approved"), Ok("Processing"), Ok("Issued")));

        Assert.Equal(1, error.Split("Approved", StringSplitOptions.None).Length - 1);
        Assert.Equal(1, error.Split("Processing", StringSplitOptions.None).Length - 1);
    }

    [Fact]
    public async Task ARequestRejectedDuringIssuance_Exits1_WithItsFailureReason()
    {
        var (exit, output, error) = await Run(new Script(Ok("Processing"), Ok("Rejected", failure: "signing failed")));

        Assert.Equal(1, exit);
        Assert.DoesNotContain("issued", output, StringComparison.Ordinal);
        Assert.Contains($"failed    {RequestGuid}", error, StringComparison.Ordinal);
        Assert.Contains("rejected: signing failed", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARejectionWithoutAReason_SaysSo()
    {
        var (exit, _, error) = await Run(new Script(Ok("Rejected")));

        Assert.Equal(1, exit);
        Assert.Contains("no reason recorded", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ATimeout_Exits3_NamingTheStatusItIsStuckIn()
    {
        var (exit, output, error) = await Run(new Script(Ok("Approved")), timeoutSeconds: 5);

        Assert.Equal(3, exit);
        Assert.Contains($"timeout   {RequestGuid}", error, StringComparison.Ordinal);
        Assert.Contains("still Approved after 5 s", error, StringComparison.Ordinal);
        Assert.Contains("queue consumer", error, StringComparison.Ordinal);
        Assert.DoesNotContain("issued", output, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARequestThatVanishes_Exits1()
    {
        var (exit, _, error) = await Run(new Script((HttpStatusCode.NotFound, "{}")));

        Assert.Equal(1, exit);
        Assert.Contains("not found", error, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ARequestAlreadyIssuedInTheApproveResponse_IsReportedWithoutPolling()
    {
        var script = new Script(Ok("Issued"));
        var issued = new CertificateRequest { Id = RequestGuid, CommonName = "cli.example.com", Status = CertificateRequestStatus.Issued };

        var (exit, output, _) = await Run(script, approved: issued);

        Assert.Equal(0, exit);
        Assert.Equal(0, script.Calls);
        Assert.Contains($"issued    {RequestGuid}", output, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0, 0, 0)]
    [InlineData(0, 3, 3)]
    [InlineData(3, 0, 3)]
    [InlineData(1, 3, 1)]
    [InlineData(3, 1, 1)]
    [InlineData(3, 3, 3)]
    [InlineData(1, 0, 1)]
    public void SeveralIds_ExitWithTheWorstResult_FailureOverTimeoutOverSuccess(int a, int b, int expected) =>
        Assert.Equal(expected, ApprovalWait.Merge(a, b));

    [Theory]
    [InlineData(1, null)]
    [InlineData(60, null)]
    [InlineData(3600, null)]
    [InlineData(0, "between 1 and 3600")]
    [InlineData(-5, "between 1 and 3600")]
    [InlineData(3601, "between 1 and 3600")]
    public void TheTimeout_MustBeBetween1And3600Seconds(int seconds, string? expectedError)
    {
        var error = ApprovalWait.ValidateTimeout(seconds);

        if (expectedError is null) Assert.Null(error);
        else Assert.Contains(expectedError, error, StringComparison.Ordinal);
    }

    [Fact]
    public void ApproveHasTheWaitOptions_AndTheHelpExplainsTheExitCodes()
    {
        var approve = RequestsCommands.Build(new Option<string?>("--api-url"), new Option<string?>("--identity-url"),
            new Option<string?>("--token"), new Option<string>("--output")).Subcommands.Single(c => c.Name == "approve");

        Assert.Contains(approve.Options, o => o.Name == "--wait");
        Assert.Contains(approve.Options, o => o.Name == "--timeout");
        Assert.Contains("3 with --wait", approve.Description, StringComparison.Ordinal);
        Assert.Empty(approve.Parse($"{RequestGuid} --wait --timeout 30").Errors);
        Assert.Empty(approve.Parse($"{RequestGuid}").Errors);
    }
}
