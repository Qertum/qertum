using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class NoticeCommandTests
{
    private sealed class Api(string body, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public List<string> Calls { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Calls.Add($"{request.Method} {request.RequestUri!.PathAndQuery}");
            return Task.FromResult(new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") });
        }
    }

    private static (CertificateRequestsApiClient Client, Api Handler) Client(string body, HttpStatusCode status = HttpStatusCode.OK)
    {
        var handler = new Api(body, status);
        return (new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") }, new FakeTimeProvider()), handler);
    }

    private const string TwoNotices = """
        {"items":[
          {"id":"11111111-1111-1111-1111-111111111111","requestId":"22222222-2222-2222-2222-222222222222","kind":"Expiring","step":14,"status":"Open","commonName":"a.contoso.local","createdAtUtc":"2026-10-14T09:00:00Z","ownerTeam":"Platform","contactEmail":"ops@contoso.local"},
          {"id":"33333333-3333-3333-3333-333333333333","requestId":"44444444-4444-4444-4444-444444444444","kind":"RenewalFailed","step":2,"status":"Open","commonName":null,"createdAtUtc":"2026-10-13T09:00:00Z"}
        ],"totalCount":2,"page":1,"pageSize":200}
        """;

    [Fact]
    public async Task List_PrintsOneLinePerNotice_WithTheContactOrUnknown()
    {
        var (client, handler) = Client(TwoNotices);
        var output = new StringWriter();

        var exit = await NoticeCommands.RunListAsync(client, NoticeStatus.Open, null, json: false, output, new StringWriter(), TestContext.Current.CancellationToken);

        var text = output.ToString();
        Assert.Equal(0, exit);
        Assert.Equal(["GET /v1/notices?page=1&pageSize=200&status=Open"], handler.Calls);
        Assert.Contains("a.contoso.local", text);
        Assert.Contains("expires within 14 days", text);
        Assert.Contains("Platform", text);
        Assert.Contains("ops@contoso.local", text);
        Assert.Contains("renewal failed (level 2)", text);
        Assert.Contains("Unknown", text);
    }

    [Fact]
    public async Task List_PassesTheKindFilter()
    {
        var (client, handler) = Client(TwoNotices);

        await NoticeCommands.RunListAsync(client, null, NoticeKind.RenewalStalled, false, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);

        Assert.Equal(["GET /v1/notices?page=1&pageSize=200&kind=RenewalStalled"], handler.Calls);
    }

    [Fact]
    public async Task List_Json_PrintsThePageObject()
    {
        var (client, _) = Client(TwoNotices);
        var output = new StringWriter();

        var exit = await NoticeCommands.RunListAsync(client, NoticeStatus.Open, null, json: true, output, new StringWriter(), TestContext.Current.CancellationToken);

        using var doc = JsonDocument.Parse(output.ToString());
        Assert.Equal(0, exit);
        Assert.Equal(2, doc.RootElement.GetProperty("totalCount").GetInt32());
        Assert.Equal("Expiring", doc.RootElement.GetProperty("items")[0].GetProperty("kind").GetString());
    }

    [Fact]
    public async Task List_WithNothing_SaysSo()
    {
        var (client, _) = Client("""{"items":[],"totalCount":0,"page":1,"pageSize":200}""");
        var output = new StringWriter();

        var exit = await NoticeCommands.RunListAsync(client, NoticeStatus.Open, null, false, output, new StringWriter(), TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Contains("No open notices", output.ToString());
    }

    [Fact]
    public async Task List_WhenThereAreMoreThanOnePage_SaysHowManyWereShown()
    {
        var (client, _) = Client("""{"items":[{"id":"11111111-1111-1111-1111-111111111111","requestId":"22222222-2222-2222-2222-222222222222","kind":"Expiring","step":7,"status":"Open","commonName":"a","createdAtUtc":"2026-10-14T09:00:00Z"}],"totalCount":450,"page":1,"pageSize":200}""");
        var output = new StringWriter();

        await NoticeCommands.RunListAsync(client, null, null, false, output, new StringWriter(), TestContext.Current.CancellationToken);

        Assert.Contains("showing 1 of 450", output.ToString());
    }

    [Fact]
    public async Task List_Forbidden_ThrowsTheProblem()
    {
        var (client, _) = Client("", HttpStatusCode.Forbidden);

        var problem = await Assert.ThrowsAsync<ApiProblemException>(() => NoticeCommands.RunListAsync(
            client, null, null, false, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken));

        Assert.Equal(HttpStatusCode.Forbidden, problem.StatusCode);
    }
}
