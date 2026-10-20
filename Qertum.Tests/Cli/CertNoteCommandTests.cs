using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Qertum.Cli.Commands;
using Qertum.Services;

namespace Qertum.Tests.Cli;

public sealed class CertNoteCommandTests
{
    private static readonly Guid RequestId = Guid.Parse("3f2c9a1e-0000-0000-0000-000000000000");
    private static readonly NoteId NoteId = new(Guid.Parse("4a4a4a4a-0000-0000-0000-000000000000"));

    private const string StoredNote = """{"id":"4a4a4a4a-0000-0000-0000-000000000000","requestId":"3f2c9a1e-0000-0000-0000-000000000000","body":"hello","authorSubject":"sub-alice","authorName":"Alice","createdAtUtc":"2026-10-14T12:00:00Z","updatedAtUtc":"2026-10-14T12:00:00Z"}""";

    private sealed class Api(HttpStatusCode status, string body) : HttpMessageHandler
    {
        public List<string> Calls { get; } = [];
        public string? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastBody = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Calls.Add($"{request.Method} {request.RequestUri!.PathAndQuery}");
            return new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        }
    }

    private static (CertificateRequestsApiClient Client, Api Handler) Client(HttpStatusCode status, string body = "")
    {
        var handler = new Api(status, body);
        return (new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("https://api.test/") }, new FakeTimeProvider()), handler);
    }

    [Fact]
    public async Task Add_PostsTheText_AndPrintsTheNoteId()
    {
        var (client, handler) = Client(HttpStatusCode.Created, StoredNote);
        var output = new StringWriter();

        var exit = await CertNoteCommands.RunAddAsync(client, RequestId, "hello", output, new StringWriter(), TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Equal([$"POST /v1/certificate-requests/{RequestId}/notes"], handler.Calls);
        Assert.Equal("hello", JsonDocument.Parse(handler.LastBody!).RootElement.GetProperty("body").GetString());
        Assert.Contains(NoteId.ToString(), output.ToString());
    }

    [Fact]
    public async Task Edit_PutsTheText()
    {
        var (client, handler) = Client(HttpStatusCode.OK, StoredNote);

        var exit = await CertNoteCommands.RunEditAsync(client, RequestId, NoteId, "changed", new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Equal([$"PUT /v1/certificate-requests/{RequestId}/notes/{NoteId}"], handler.Calls);
        Assert.Equal("changed", JsonDocument.Parse(handler.LastBody!).RootElement.GetProperty("body").GetString());
    }

    [Fact]
    public async Task Edit_OfAnUnknownNote_ExitsOne()
    {
        var (client, _) = Client(HttpStatusCode.NotFound, "{}");
        var error = new StringWriter();

        var exit = await CertNoteCommands.RunEditAsync(client, RequestId, NoteId, "x", new StringWriter(), error, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Contains("no such note", error.ToString());
    }

    [Fact]
    public async Task Delete_SendsDelete_AndSaysSo()
    {
        var (client, handler) = Client(HttpStatusCode.NoContent);
        var output = new StringWriter();

        var exit = await CertNoteCommands.RunDeleteAsync(client, RequestId, NoteId, output, new StringWriter(), TestContext.Current.CancellationToken);

        Assert.Equal(0, exit);
        Assert.Equal([$"DELETE /v1/certificate-requests/{RequestId}/notes/{NoteId}"], handler.Calls);
        Assert.Contains("deleted", output.ToString());
    }

    [Fact]
    public async Task Delete_OfAnUnknownNote_ExitsOne()
    {
        var (client, _) = Client(HttpStatusCode.NotFound, "{}");
        var error = new StringWriter();

        var exit = await CertNoteCommands.RunDeleteAsync(client, RequestId, NoteId, new StringWriter(), error, TestContext.Current.CancellationToken);

        Assert.Equal(1, exit);
        Assert.Contains("no such note", error.ToString());
    }

    [Fact]
    public async Task NotTheAuthor_ThrowsTheProblem_WhoseForbiddenHintSaysOnlyTheAuthorMayChangeIt()
    {
        var (client, _) = Client(HttpStatusCode.Forbidden);

        var problem = await Assert.ThrowsAsync<ApiProblemException>(() => CertNoteCommands.RunDeleteAsync(
            client, RequestId, NoteId, new StringWriter(), new StringWriter(), TestContext.Current.CancellationToken));

        var lines = Qertum.Cli.Api.CliApi.FormatProblem(problem, CertNoteCommands.ForbiddenHint);
        Assert.Contains("author", lines[0]);
    }

    [Fact]
    public void History_FormatsANoteOnOneLine_WithItsIdAndEditedMarker()
    {
        var entry = new TimelineEntry
        {
            Kind = TimelineEntryKind.Note, Action = "Note", PerformedBy = "Alice", NoteId = NoteId, Edited = true,
            Detail = "first line\nsecond line"
        };

        var text = CertNoteCommands.DescribeForHistory(entry);

        Assert.DoesNotContain('\n', text);
        Assert.Contains(NoteId.ToString(), text);
        Assert.Contains("(edited)", text);
        Assert.Contains("first line / second line", text);
    }

    [Theory]
    [InlineData("ok\rFORGED")]
    [InlineData("a\r\nb")]
    [InlineData("a\nb\rc")]
    public void History_NeverPrintsACarriageReturnOrLineFeed(string detail)
    {
        var entry = new TimelineEntry { Kind = TimelineEntryKind.Note, Action = "Note", NoteId = NoteId, Detail = detail };

        var text = CertNoteCommands.DescribeForHistory(entry);

        Assert.DoesNotContain('\r', text);
        Assert.DoesNotContain('\n', text);
    }
}
