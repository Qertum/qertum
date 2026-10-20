using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class CertificateTimelineNotesTests
{
    private static TimelineAccess As(string? subject) => new(CanEditSettings: false, CanSeeKeyExports: false, CallerSubject: subject);

    private static CertificateNote Note(CertificateRequest request, string body, string subject, string name, DateTime at, DateTime? updated = null) => new()
    {
        RequestId = request.Id, Body = body, AuthorSubject = subject, AuthorName = name, CreatedAtUtc = at, UpdatedAtUtc = updated ?? at
    };

    [Fact]
    public async Task Notes_AreEntriesInOrder_WithAuthorBodyAndTheCallersMine()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var request = await host.RequestAsync("a.contoso.local");
        var first = Note(request, "first note", "sub-alice", "Alice", host.Now.AddHours(1));
        var second = Note(request, "second\nnote", "sub-bob", "Bob", host.Now.AddHours(2));
        host.Db.CertificateNotes.AddRange(second, first);
        await host.Db.SaveChangesAsync(ct);

        var asAlice = (await new CertificateTimelineService(host.Db).GetAsync(request.Id, As("sub-alice"), ct))!;

        var notes = asAlice.Entries.Where(e => e.Kind == TimelineEntryKind.Note).ToList();
        Assert.Equal(["first note", "second\nnote"], notes.Select(n => n.Detail));
        Assert.Equal(["Alice", "Bob"], notes.Select(n => n.PerformedBy));
        Assert.Equal([true, false], notes.Select(n => n.Mine));
        Assert.Equal([first.Id, second.Id], notes.Select(n => n.NoteId!.Value));
        Assert.All(notes, n => Assert.False(n.Edited));
        Assert.True(asAlice.Entries.IndexOf(notes[0]) < asAlice.Entries.IndexOf(notes[1]));
    }

    [Fact]
    public async Task ACallerWithNoSubject_OwnsNoNote()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var request = await host.RequestAsync("a.contoso.local");
        host.Db.CertificateNotes.Add(Note(request, "x", "sub-alice", "Alice", host.Now));
        await host.Db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(host.Db).GetAsync(request.Id, As(null), ct))!;

        Assert.False(Assert.Single(timeline.Entries, e => e.Kind == TimelineEntryKind.Note).Mine);
    }

    [Fact]
    public async Task AnEditedNote_StaysAtItsCreationTime_AndIsMarkedEdited()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var request = await host.RequestAsync("a.contoso.local");
        var created = host.Now.AddHours(1);
        var edited = host.Now.AddHours(5);
        host.Db.CertificateNotes.Add(Note(request, "later fixed", "sub-alice", "Alice", created, edited));
        await host.Db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(host.Db).GetAsync(request.Id, As("sub-alice"), ct))!;

        var entry = Assert.Single(timeline.Entries, e => e.Kind == TimelineEntryKind.Note);
        Assert.Equal(created, entry.OccurredAtUtc);
        Assert.True(entry.Edited);
        Assert.Equal(edited, entry.UpdatedAtUtc);
    }

    [Fact]
    public async Task OnlyThisRequestsNotes_AreShown()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var request = await host.RequestAsync("a.contoso.local");
        var other = await host.RequestAsync("b.contoso.local");
        host.Db.CertificateNotes.AddRange(
            Note(request, "mine", "sub-alice", "Alice", host.Now), Note(other, "theirs", "sub-alice", "Alice", host.Now));
        await host.Db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(host.Db).GetAsync(request.Id, As("sub-alice"), ct))!;

        Assert.Equal("mine", Assert.Single(timeline.Entries, e => e.Kind == TimelineEntryKind.Note).Detail);
    }

    [Fact]
    public async Task TheNoteAddedAndEditedAuditRows_AreHidden_ButTheDeletedOneIsShown()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var request = await host.RequestAsync("a.contoso.local");
        foreach (var action in new[] { "NoteAdded", "NoteEdited", "NoteDeleted" })
        {
            host.Db.LifecycleEvents.Add(new LifecycleEvent
            {
                Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Audit, OccurredAtUtc = host.Now, SubjectType = LifecycleSubjectTypes.CertificateRequest,
                SubjectId = request.Id, Action = action, PerformedBy = "Alice", Detail = $"Note {Guid.NewGuid()}"
            });
        }
        await host.Db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(host.Db).GetAsync(request.Id, As("sub-alice"), ct))!;

        var actions = timeline.Entries.Select(e => e.Action).ToList();
        Assert.DoesNotContain("NoteAdded", actions);
        Assert.DoesNotContain("NoteEdited", actions);
        Assert.Contains("NoteDeleted", actions);
    }

    [Fact]
    public async Task Related_RequestsCarryTheirNoteCount()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var original = await host.RequestAsync("a.contoso.local", CertificateRequestStatus.Issued);
        var renewal = new CertificateRequest
        {
            CommonName = "renewal-of-a", RequestedBy = "alice", Type = "WebServer", Status = CertificateRequestStatus.Pending, RenewedFromId = original.Id
        };
        host.Db.CertificateRequests.Add(renewal);
        host.Db.CertificateNotes.AddRange(
            Note(original, "one", "sub-alice", "Alice", host.Now), Note(original, "two", "sub-bob", "Bob", host.Now));
        await host.Db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(host.Db).GetAsync(renewal.Id, As("sub-alice"), ct))!;

        Assert.Equal(2, Assert.Single(timeline.Related).NoteCount);
    }

    [Fact]
    public async Task Notes_AreNeverListedAsWithheld()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var host = await NoteTestHost.CreateAsync();
        var request = await host.RequestAsync("a.contoso.local");
        host.Db.CertificateNotes.Add(Note(request, "x", "sub-alice", "Alice", host.Now));
        await host.Db.SaveChangesAsync(ct);

        var timeline = (await new CertificateTimelineService(host.Db).GetAsync(request.Id, As("sub-bob"), ct))!;

        Assert.DoesNotContain(timeline.Withheld, w => w.Section.ToString().Contains("Note"));
        Assert.Contains(timeline.Entries, e => e.Kind == TimelineEntryKind.Note);
    }
}
