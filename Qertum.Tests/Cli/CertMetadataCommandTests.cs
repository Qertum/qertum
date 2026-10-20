using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class CertMetadataCommandTests
{
    private static readonly CertificateRequestId Id = new(Guid.Parse("3f2c9a1e-0000-0000-0000-000000000000"));

    private sealed class Api(Func<HttpMethod, string, string?, (HttpStatusCode Status, string Body)> answer) : HttpMessageHandler
    {
        public List<string> Calls { get; } = [];
        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Calls.Add($"{request.Method} {request.RequestUri!.PathAndQuery}");
            var (status, body) = answer(request.Method, request.RequestUri.PathAndQuery, LastBody);
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }

    private sealed class Harness(Func<HttpMethod, string, string?, (HttpStatusCode, string)> answer)
    {
        public Api Handler { get; } = new(answer);
        public StringWriter Out { get; } = new();
        public StringWriter Err { get; } = new();
        public CertificateRequestsApiClient Client => new(
            new HttpClient(Handler) { BaseAddress = new Uri("https://api.test/") }, new FakeTimeProvider());
    }

    private static string RequestJson(string metadataJson) =>
        $$"""{"id":"{{Id.Value}}","commonName":"a.local","requestedBy":"alice","status":"Issued","metadata":{{metadataJson}}}""";

    [Fact]
    public async Task Show_PrintsEveryField_AndUnknownForTheOnesNobodyRecorded()
    {
        var h = new Harness((_, _, _) => (HttpStatusCode.OK, RequestJson("""{"ownerTeam":"Platform"}""")));

        var exit = await CertMetadataCommands.RunShowAsync(h.Client, Id, json: false, h.Out, h.Err, TestContext.Current.CancellationToken);

        var text = h.Out.ToString();
        Assert.Equal(0, exit);
        Assert.Contains("Owner Team", text);
        Assert.Contains("Platform", text);
        Assert.Equal(5, text.Split('\n').Count(l => l.TrimEnd().EndsWith("Unknown", StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Show_Json_PrintsTheMetadataObject()
    {
        var h = new Harness((_, _, _) => (HttpStatusCode.OK, RequestJson("""{"ownerTeam":"Platform","ticketReference":"OPS-1"}""")));

        var exit = await CertMetadataCommands.RunShowAsync(h.Client, Id, json: true, h.Out, h.Err, TestContext.Current.CancellationToken);

        using var doc = JsonDocument.Parse(h.Out.ToString());
        Assert.Equal(0, exit);
        Assert.Equal("Platform", doc.RootElement.GetProperty("ownerTeam").GetString());
        Assert.Equal("OPS-1", doc.RootElement.GetProperty("ticketReference").GetString());
    }

    [Fact]
    public async Task Show_UnknownId_ExitsOne()
    {
        var h = new Harness((_, _, _) => (HttpStatusCode.NotFound, "{}"));

        var exit = await CertMetadataCommands.RunShowAsync(h.Client, Id, json: false, h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Contains($"no certificate request with ID {Id}", h.Err.ToString());
    }

    [Fact]
    public async Task Set_SendsTheWholeSet_SoOptionsLeftOutAreSentAsNull()
    {
        var h = new Harness((_, _, _) => (HttpStatusCode.OK, """{"ownerTeam":"Platform","ticketReference":"OPS-1"}"""));

        var exit = await CertMetadataCommands.RunSetAsync(h.Client, Id,
            new CertificateMetadata { OwnerTeam = "Platform", TicketReference = "OPS-1" }, h.Out, h.Err, TestContext.Current.CancellationToken);

        using var sent = JsonDocument.Parse(h.Handler.LastBody!);
        Assert.Equal(0, exit);
        Assert.Equal([$"PUT /v1/certificate-requests/{Id}/metadata"], h.Handler.Calls);
        Assert.Equal("Platform", sent.RootElement.GetProperty("ownerTeam").GetString());
        Assert.Equal(JsonValueKind.Null, sent.RootElement.GetProperty("purpose").ValueKind);
        Assert.Contains("updated", h.Out.ToString());
    }

    [Fact]
    public async Task Set_WithNothing_ClearsEverything()
    {
        var h = new Harness((_, _, _) => (HttpStatusCode.OK, "{}"));

        await CertMetadataCommands.RunSetAsync(h.Client, Id, new CertificateMetadata(), h.Out, h.Err, TestContext.Current.CancellationToken);

        using var sent = JsonDocument.Parse(h.Handler.LastBody!);
        Assert.All(sent.RootElement.EnumerateObject(), p => Assert.Equal(JsonValueKind.Null, p.Value.ValueKind));
    }

    [Fact]
    public async Task Set_UnknownId_ExitsOne()
    {
        var h = new Harness((_, _, _) => (HttpStatusCode.NotFound, "{}"));

        var exit = await CertMetadataCommands.RunSetAsync(h.Client, Id, new CertificateMetadata(), h.Out, h.Err, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Contains($"no certificate request with ID {Id}", h.Err.ToString());
    }

    [Fact]
    public async Task Set_Refused_ThrowsTheProblem_AndTheForbiddenHintNamesWhoMayEdit()
    {
        var h = new Harness((_, _, _) => (HttpStatusCode.Forbidden, ""));

        var problem = await Assert.ThrowsAsync<ApiProblemException>(() => CertMetadataCommands.RunSetAsync(
            h.Client, Id, new CertificateMetadata(), h.Out, h.Err, TestContext.Current.CancellationToken));

        var lines = Qertum.Cli.Api.CliApi.FormatProblem(problem, CertMetadataCommands.ForbiddenHint);
        Assert.Equal(HttpStatusCode.Forbidden, problem.StatusCode);
        Assert.Contains("certificates.manage", lines[0]);
        Assert.Contains("requester", lines[0]);
    }
}
