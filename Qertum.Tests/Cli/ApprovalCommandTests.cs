using System.CommandLine;
using System.Net;
using System.Text;
using Qertum.Cli;
using Qertum.Cli.Api;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class ApprovalCommandTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Recording(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public HttpMethod? Method { get; private set; }
        public string? PathAndQuery { get; private set; }
        public string? Body { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Method = request.Method;
            PathAndQuery = request.RequestUri!.PathAndQuery;
            Body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }

    private static (CertificateRequestsApiClient Client, Recording Handler) ClientFor(HttpStatusCode status, string body)
    {
        var handler = new Recording(status, body);
        return (new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") }), handler);
    }

    private const string OneApproval = """
        {"id":"7e2c6a38-0d4f-4a3e-9d57-0c1c8f0b2a11","operation":"bulk-revoke","targetId":"3f1d9c0e-0000-4000-8000-000000000001",
         "targetLabel":"bulk revoke of 12 certificates","note":"cleanup","requestedByName":"alice","requestedAtUtc":"2026-10-18T10:00:00Z",
         "status":"Pending","decidedByName":null,"decidedAtUtc":null,"decisionNote":null,"grantExpiresAtUtc":null,"usedAtUtc":null}
        """;

    [Fact]
    public void ExposesTheApprovalsGroup()
    {
        var group = CliRoot.Build().Subcommands.Single(c => c.Name == "approvals");
        Assert.Equal(["approve", "deny", "list", "request", "switch"], group.Subcommands.Select(c => c.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Client_Request_PostsTheBody()
    {
        var (client, handler) = ClientFor(HttpStatusCode.Created, OneApproval);

        var created = await client.RequestApprovalAsync(new RequestApprovalRequest("bulk-revoke", "3f1d9c0e-0000-4000-8000-000000000001", "cleanup"), Ct);

        Assert.Equal(HttpMethod.Post, handler.Method);
        Assert.Equal("/v1/approvals", handler.PathAndQuery);
        Assert.Contains("\"operation\":\"bulk-revoke\"", handler.Body);
        Assert.Equal(ApprovalStatus.Pending, created.Status);
    }

    [Fact]
    public async Task Client_List_SendsTheFilters()
    {
        var (client, handler) = ClientFor(HttpStatusCode.OK, """{"items":[],"totalCount":0,"page":1,"pageSize":50}""");

        await client.GetApprovalsAsync(ApprovalStatus.Pending, mine: true, 1, 50, Ct);

        Assert.Equal(HttpMethod.Get, handler.Method);
        Assert.Equal("/v1/approvals?page=1&pageSize=50&status=Pending&mine=true", handler.PathAndQuery);
    }

    [Theory]
    [InlineData(true, "approve")]
    [InlineData(false, "deny")]
    public async Task Client_Decide_PostsToTheRightRoute(bool approve, string route)
    {
        var (client, handler) = ClientFor(HttpStatusCode.OK, OneApproval);
        var id = new ApprovalRequestId(Guid.Parse("7e2c6a38-0d4f-4a3e-9d57-0c1c8f0b2a11"));

        await client.DecideApprovalAsync(id, approve, "fine", Ct);

        Assert.Equal(HttpMethod.Post, handler.Method);
        Assert.Equal($"/v1/approvals/{id}/{route}", handler.PathAndQuery);
        Assert.Equal("{\"note\":\"fine\"}", handler.Body);
    }

    [Fact]
    public async Task Client_Switch_PutsTheFlag()
    {
        var (client, handler) = ClientFor(HttpStatusCode.OK, "{}");

        await client.SetTwoPersonApprovalAsync(true, Ct);

        Assert.Equal(HttpMethod.Put, handler.Method);
        Assert.Equal("/v1/settings/two-person-approval", handler.PathAndQuery);
        Assert.Equal("{\"enabled\":true}", handler.Body);
    }

    [Fact]
    public async Task AnApprovalRequiredRefusal_IsParsedIntoTheException_AndTheCliPrintsTheCommandToRun()
    {
        var (client, _) = ClientFor(HttpStatusCode.Forbidden,
            """{"title":"Approval required","detail":"A second administrator must approve.","status":403,"operation":"bulk-revoke","targetId":"abc"}""");

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => client.GetApprovalAsync(new ApprovalRequestId(Guid.NewGuid()), Ct));

        Assert.Equal("bulk-revoke", ex.Approval?.Operation);
        Assert.Equal("abc", ex.Approval?.TargetId);
        var lines = CliApi.FormatProblem(ex, null);
        Assert.Contains("  run: qca approvals request bulk-revoke --target abc --note \"<why>\"", lines);
        Assert.Contains(lines, l => l.Contains("second administrator", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnOrdinary403_HasNoApprovalHint()
    {
        var (client, _) = ClientFor(HttpStatusCode.Forbidden, """{"title":"Forbidden","status":403}""");

        var ex = await Assert.ThrowsAsync<ApiProblemException>(() => client.GetApprovalAsync(new ApprovalRequestId(Guid.NewGuid()), Ct));

        Assert.Null(ex.Approval);
        Assert.DoesNotContain(CliApi.FormatProblem(ex, null), l => l.Contains("approvals request", StringComparison.Ordinal));
    }

    [Fact]
    public async Task List_PrintsOneLinePerApproval_AndJsonAsAPage()
    {
        var (client, _) = ClientFor(HttpStatusCode.OK, $$"""{"items":[{{OneApproval}}],"totalCount":1,"page":1,"pageSize":50}""");
        var table = new StringWriter();
        var json = new StringWriter();

        Assert.Equal(0, await ApprovalCommands.RunListAsync(client, null, false, json: false, table, TextWriter.Null, Ct));
        Assert.Equal(0, await ApprovalCommands.RunListAsync(client, null, false, json: true, json, TextWriter.Null, Ct));

        var line = Assert.Single(table.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries));
        Assert.Contains("7e2c6a38-0d4f-4a3e-9d57-0c1c8f0b2a11", line);
        Assert.Contains("bulk-revoke", line);
        Assert.Contains("Pending", line);
        Assert.Contains("alice", line);
        Assert.Contains("\"totalCount\": 1", json.ToString());
    }

    [Fact]
    public async Task List_SaysSoWhenThereIsNothing()
    {
        var (client, _) = ClientFor(HttpStatusCode.OK, """{"items":[],"totalCount":0,"page":1,"pageSize":50}""");
        var output = new StringWriter();

        await ApprovalCommands.RunListAsync(client, null, false, json: false, output, TextWriter.Null, Ct);

        Assert.Contains("No approvals.", output.ToString());
    }

    [Theory]
    [InlineData("on", true, true)]
    [InlineData("OFF", true, false)]
    [InlineData("maybe", false, false)]
    public void ParseSwitch_NamesBothStates_AndRefusesTheRest(string text, bool ok, bool enabled)
    {
        Assert.Equal(ok, ApprovalCommands.ParseSwitch(text, out var parsed));
        if (ok) Assert.Equal(enabled, parsed);
    }
}
