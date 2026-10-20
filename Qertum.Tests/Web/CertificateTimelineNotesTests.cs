using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

public sealed class CertificateTimelineNotesTests
{
    private static readonly Guid RequestId = Guid.Parse("3f2c9a1e-0000-0000-0000-000000000000");
    private static readonly DateTime At = new(2026, 10, 14, 12, 0, 0, DateTimeKind.Utc);

    private sealed class Api(Func<CertificateTimelineResponse> timeline, Func<HttpRequestMessage, HttpResponseMessage>? write = null) : HttpMessageHandler
    {
        public List<(string Method, string Path, string? Body)> Calls { get; } = [];

        /// <summary>When set, writes wait for it, so a test can act while a save is still in flight.</summary>
        public TaskCompletionSource? Gate { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            Calls.Add((request.Method.Method, request.RequestUri!.AbsolutePath, body));
            if (request.Method != HttpMethod.Get && Gate is not null) await Gate.Task;
            if (request.Method == HttpMethod.Get)
                return Json(HttpStatusCode.OK, JsonSerializer.Serialize(timeline(), JsonSerializerOptions.Web));
            if (write is not null) return write(request);
            if (request.Method == HttpMethod.Delete) return new HttpResponseMessage(HttpStatusCode.NoContent);
            return Json(request.Method == HttpMethod.Post ? HttpStatusCode.Created : HttpStatusCode.OK, StoredNote);
        }
    }

    private const string StoredNote = """{"id":"4a4a4a4a-0000-0000-0000-000000000000","requestId":"3f2c9a1e-0000-0000-0000-000000000000","body":"x","authorSubject":"sub-alice","authorName":"Alice","createdAtUtc":"2026-10-14T12:00:00Z","updatedAtUtc":"2026-10-14T12:00:00Z"}""";

    private static HttpResponseMessage Json(HttpStatusCode status, string body, string? correlationId = null)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (correlationId is not null) response.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId);
        return response;
    }

    private static CertificateTimelineResponse Timeline(IEnumerable<TimelineEntry> entries, params TimelineCertificateSummary[] related) => new()
    {
        Subject = new TimelineCertificateSummary { Id = RequestId, CommonName = "a.contoso.local" },
        Entries = [.. entries], Related = [.. related], Completeness = TimelineCompleteness.Full
    };

    private static TimelineEntry NoteEntry(string body, bool mine, bool edited = false) => new()
    {
        OccurredAtUtc = At, Kind = TimelineEntryKind.Note, Action = "Note", PerformedBy = "Alice", Detail = body,
        NoteId = new NoteId(Guid.Parse("4a4a4a4a-0000-0000-0000-000000000000")), Mine = mine, Edited = edited,
        UpdatedAtUtc = edited ? At.AddHours(3) : At
    };

    private static (IRenderedComponent<CertificateTimeline> Cut, Api Handler) Render(Func<CertificateTimelineResponse> timeline, Func<HttpRequestMessage, HttpResponseMessage>? write = null)
    {
        var handler = new Api(timeline, write);
        var context = new BunitContext();
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://api.test/") }));
        var cut = context.Render<CertificateTimeline>(p => p.Add(c => c.RequestId, RequestId));
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='note-form']")));
        return (cut, handler);
    }

    private static int Gets(Api handler) => handler.Calls.Count(c => c.Method == "GET");

    [Fact]
    public void ANote_IsShownAsText_NotMarkup_WithLineBreaksKept()
    {
        var (cut, _) = Render(() => Timeline([NoteEntry("<b>bold</b>\nsecond line", mine: false)]));

        var note = cut.Find("[data-test='timeline-note']");

        Assert.Equal("<b>bold</b>\nsecond line", note.TextContent);
        Assert.Contains("&lt;b&gt;", note.InnerHtml);
        Assert.Empty(note.QuerySelectorAll("b"));
        Assert.Contains("timeline-note", note.ClassList);
    }

    [Fact]
    public void AnEditedNote_ShowsTheEditedMarker_AndAnUneditedOneDoesNot()
    {
        var (edited, _) = Render(() => Timeline([NoteEntry("x", mine: false, edited: true)]));
        var (plain, _) = Render(() => Timeline([NoteEntry("x", mine: false)]));

        Assert.Contains("edited", edited.Find("[data-test='timeline-edited']").TextContent);
        Assert.Empty(plain.FindAll("[data-test='timeline-edited']"));
    }

    [Fact]
    public void OnlyTheCallersOwnNotes_GetEditAndDeleteControls()
    {
        var (cut, _) = Render(() => Timeline([NoteEntry("mine", mine: true), NoteEntry("theirs", mine: false)]));

        Assert.Single(cut.FindAll("[data-test='note-edit']"));
        Assert.Single(cut.FindAll("[data-test='note-delete']"));
    }

    [Fact]
    public async Task Add_PostsTheText_ClearsTheBox_AndReloads()
    {
        var (cut, handler) = Render(() => Timeline([]));
        cut.Find("[data-test='note-text']").Input("Renewed after the outage");

        await cut.Find("[data-test='note-add']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Equal(2, Gets(handler)));
        var post = Assert.Single(handler.Calls, c => c.Method == "POST");
        Assert.Equal($"/v1/certificate-requests/{RequestId}/notes", post.Path);
        Assert.Equal("Renewed after the outage", JsonDocument.Parse(post.Body!).RootElement.GetProperty("body").GetString());
        Assert.Equal("", cut.Find("[data-test='note-text']").GetAttribute("value") ?? "");
    }

    [Fact]
    public void Add_IsDisabled_WhileTheBoxIsEmpty()
    {
        var (cut, handler) = Render(() => Timeline([]));

        Assert.True(cut.Find("[data-test='note-add']").HasAttribute("disabled"));
        Assert.DoesNotContain(handler.Calls, c => c.Method == "POST");
    }

    [Fact]
    public async Task Edit_OpensAPrefilledEditor_SavesWithPut_AndReloads()
    {
        var (cut, handler) = Render(() => Timeline([NoteEntry("first", mine: true)]));

        await cut.Find("[data-test='note-edit']").ClickAsync(new());
        Assert.Equal("first", cut.Find("[data-test='note-edit-text']").GetAttribute("value"));
        cut.Find("[data-test='note-edit-text']").Input("second");
        await cut.Find("[data-test='note-save']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Equal(2, Gets(handler)));
        var put = Assert.Single(handler.Calls, c => c.Method == "PUT");
        Assert.Equal($"/v1/certificate-requests/{RequestId}/notes/4a4a4a4a-0000-0000-0000-000000000000", put.Path);
        Assert.Equal("second", JsonDocument.Parse(put.Body!).RootElement.GetProperty("body").GetString());
        Assert.Empty(cut.FindAll("[data-test='note-edit-text']"));
    }

    [Fact]
    public async Task Edit_Cancel_DiscardsTheChange_WithoutACall()
    {
        var (cut, handler) = Render(() => Timeline([NoteEntry("first", mine: true)]));
        await cut.Find("[data-test='note-edit']").ClickAsync(new());
        cut.Find("[data-test='note-edit-text']").Input("typed but not saved");

        await cut.Find("[data-test='note-cancel']").ClickAsync(new());

        Assert.Empty(cut.FindAll("[data-test='note-edit-text']"));
        Assert.Equal("first", cut.Find("[data-test='timeline-note']").TextContent);
        Assert.DoesNotContain(handler.Calls, c => c.Method == "PUT");
    }

    [Fact]
    public async Task Delete_AsksFirst_ThenSendsDelete_AndReloads()
    {
        var (cut, handler) = Render(() => Timeline([NoteEntry("bye", mine: true)]));

        await cut.Find("[data-test='note-delete']").ClickAsync(new());
        Assert.NotEmpty(cut.FindAll("[data-test='note-delete-panel']"));
        Assert.DoesNotContain(handler.Calls, c => c.Method == "DELETE");
        await cut.Find("[data-test='note-delete-confirm']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Equal(2, Gets(handler)));
        var delete = Assert.Single(handler.Calls, c => c.Method == "DELETE");
        Assert.Equal($"/v1/certificate-requests/{RequestId}/notes/4a4a4a4a-0000-0000-0000-000000000000", delete.Path);
    }

    [Fact]
    public async Task Delete_KeepIt_SendsNothing()
    {
        var (cut, handler) = Render(() => Timeline([NoteEntry("stay", mine: true)]));
        await cut.Find("[data-test='note-delete']").ClickAsync(new());

        await cut.Find("[data-test='note-delete-cancel']").ClickAsync(new());

        Assert.Empty(cut.FindAll("[data-test='note-delete-panel']"));
        Assert.DoesNotContain(handler.Calls, c => c.Method == "DELETE");
    }

    [Fact]
    public async Task AFailedSave_ShowsTheMessageWithItsCorrelationId()
    {
        var (cut, _) = Render(() => Timeline([]),
            _ => Json(HttpStatusCode.BadRequest, """{"title":"Bad Request","detail":"A note cannot be empty."}""", "abc123def456"));
        cut.Find("[data-test='note-text']").Input("x");

        await cut.Find("[data-test='note-add']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Contains("(correlation id: abc123def456)", cut.Find("[data-test='note-error']").TextContent));
    }

    [Fact]
    public async Task ARefusal_SaysOnlyTheAuthorCanChangeIt()
    {
        var (cut, _) = Render(() => Timeline([NoteEntry("x", mine: true)]), _ => new HttpResponseMessage(HttpStatusCode.Forbidden));
        await cut.Find("[data-test='note-edit']").ClickAsync(new());
        cut.Find("[data-test='note-edit-text']").Input("changed");

        await cut.Find("[data-test='note-save']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.Contains("Only the author", cut.Find("[data-test='note-error']").TextContent));
    }

    [Fact]
    public void TheRelatedCard_ShowsTheNoteCount_OnlyWhenThereAreNotes()
    {
        var withNotes = new TimelineCertificateSummary { Id = Guid.NewGuid(), CommonName = "older.contoso.local", NoteCount = 3 };
        var without = new TimelineCertificateSummary { Id = Guid.NewGuid(), CommonName = "newer.contoso.local", NoteCount = 0 };
        var renewals = new[]
        {
            new TimelineEntry { OccurredAtUtc = At, Kind = TimelineEntryKind.Renewal, Action = "RenewedFrom", RelatedRequestId = withNotes.Id },
            new TimelineEntry { OccurredAtUtc = At.AddHours(1), Kind = TimelineEntryKind.Renewal, Action = "RenewedAs", RelatedRequestId = without.Id }
        };
        var (cut, _) = Render(() => Timeline(renewals, withNotes, without));

        var counts = cut.FindAll("[data-test='timeline-related-notes']");

        Assert.Equal("3 notes", Assert.Single(counts).TextContent.Trim());
    }

    [Fact]
    public void TheCard_CarriesNoInlineStyle()
    {
        var (cut, _) = Render(() => Timeline([NoteEntry("x", mine: true)]));

        Assert.DoesNotContain("style=", cut.Markup, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ASecondClick_WhileTheFirstSaveIsInFlight_DoesNotPostAgain()
    {
        var (cut, handler) = Render(() => Timeline([]));
        handler.Gate = new TaskCompletionSource();
        cut.Find("[data-test='note-text']").Input("only once");

        var first = cut.Find("[data-test='note-add']").ClickAsync(new());
        var second = cut.Find("[data-test='note-add']").ClickAsync(new());
        handler.Gate.SetResult();
        await Task.WhenAll(first, second);

        cut.WaitForAssertion(() => Assert.Equal(2, Gets(handler)));
        Assert.Single(handler.Calls, c => c.Method == "POST");
    }

    [Fact]
    public async Task TheEditorAndTheButtons_HaveNamesThatTellNotesApart()
    {
        var (cut, _) = Render(() => Timeline([NoteEntry("first", mine: true)]));

        Assert.Contains("Alice", cut.Find("[data-test='note-edit']").GetAttribute("aria-label"));
        Assert.Contains("Alice", cut.Find("[data-test='note-delete']").GetAttribute("aria-label"));
        await cut.Find("[data-test='note-edit']").ClickAsync(new());

        Assert.Contains("Alice", cut.Find("[data-test='note-edit-text']").GetAttribute("aria-label"));
    }

    [Fact]
    public async Task AFailedEdit_ShowsItsErrorBesideThatNote_NotOnlyInTheAddForm()
    {
        var (cut, _) = Render(() => Timeline([NoteEntry("x", mine: true)]), _ => new HttpResponseMessage(HttpStatusCode.Forbidden));
        await cut.Find("[data-test='note-edit']").ClickAsync(new());
        cut.Find("[data-test='note-edit-text']").Input("changed");

        await cut.Find("[data-test='note-save']").ClickAsync(new());

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='timeline-entry'] [data-test='note-error']")));
        Assert.Empty(cut.FindAll("[data-test='note-form'] [data-test='note-error']"));
    }
}
