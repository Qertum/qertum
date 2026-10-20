using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.CertificateNotes;

namespace Qertum.Tests;

public sealed class CertificateNoteServiceTests
{
    private const string Alice = "sub-alice";
    private const string Bob = "sub-bob";

    private static async Task<(NoteTestHost Host, CertificateRequest Request)> ArrangeAsync()
    {
        var host = await NoteTestHost.CreateAsync();
        return (host, await host.RequestAsync("a.contoso.local"));
    }

    [Fact]
    public async Task Add_StoresTheNormalizedNote_WithTheAuthor_AndAuditsItWithoutTheText()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;

        var result = await host.Service.AddAsync(request.Id, "  secret plan\r\nstep two  ", Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.Done, result.Outcome);
        var note = result.Note!;
        Assert.Equal("secret plan\nstep two", note.Body);
        Assert.Equal((Alice, "Alice", request.Id), (note.AuthorSubject, note.AuthorName, note.RequestId));
        Assert.Equal(note.CreatedAtUtc, note.UpdatedAtUtc);
        var (action, detail) = Assert.Single(host.Audit.Entries);
        Assert.Equal("NoteAdded", action);
        Assert.Contains(note.Id.ToString(), detail);
        Assert.DoesNotContain("secret", detail);
    }

    [Fact]
    public async Task Add_ForAnUnknownRequest_IsRequestNotFound()
    {
        await using var host = await NoteTestHost.CreateAsync();

        var result = await host.Service.AddAsync(Guid.NewGuid(), "hello", Alice, "Alice", TestContext.Current.CancellationToken);

        Assert.Equal(NoteOutcome.RequestNotFound, result.Outcome);
    }

    [Fact]
    public async Task Add_RefusesTheTwoHundredAndFirstNote()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        for (var i = 0; i < CertificateNote.MaxPerRequest; i++)
        {
            host.Db.CertificateNotes.Add(new CertificateNote
            {
                RequestId = request.Id, Body = $"n{i}", AuthorSubject = Alice, AuthorName = "Alice",
                CreatedAtUtc = host.Now, UpdatedAtUtc = host.Now
            });
        }
        await host.Db.SaveChangesAsync(ct);

        var result = await host.Service.AddAsync(request.Id, "one too many", Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.TooMany, result.Outcome);
        Assert.Equal(CertificateNote.MaxPerRequest, await host.Db.CertificateNotes.CountAsync(ct));
    }

    [Fact]
    public async Task Edit_ByTheAuthor_ChangesTheBodyAndTheEditTime_Only()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var note = (await host.Service.AddAsync(request.Id, "first", Alice, "Alice", ct)).Note!;
        host.Clock.Advance(TimeSpan.FromHours(2));
        host.Audit.Entries.Clear();

        var result = await host.Service.EditAsync(request.Id, note.Id, "second", Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.Done, result.Outcome);
        var edited = result.Note!;
        Assert.Equal("second", edited.Body);
        Assert.Equal(note.CreatedAtUtc, edited.CreatedAtUtc);
        Assert.Equal(host.Now, edited.UpdatedAtUtc);
        Assert.Equal((Alice, "Alice"), (edited.AuthorSubject, edited.AuthorName));
        var (action, detail) = Assert.Single(host.Audit.Entries);
        Assert.Equal("NoteEdited", action);
        Assert.DoesNotContain("second", detail);
        Assert.DoesNotContain("first", detail);
    }

    [Fact]
    public async Task Edit_ToTheSameText_ChangesNothingAndAuditsNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var note = (await host.Service.AddAsync(request.Id, "same", Alice, "Alice", ct)).Note!;
        host.Clock.Advance(TimeSpan.FromHours(2));
        host.Audit.Entries.Clear();

        var result = await host.Service.EditAsync(request.Id, note.Id, " same ", Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.Done, result.Outcome);
        Assert.Equal(note.CreatedAtUtc, result.Note!.UpdatedAtUtc);
        Assert.Empty(host.Audit.Entries);
    }

    [Fact]
    public async Task Edit_ByAnotherPerson_IsNotAuthor_AndChangesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var note = (await host.Service.AddAsync(request.Id, "mine", Alice, "Alice", ct)).Note!;
        host.Audit.Entries.Clear();

        var result = await host.Service.EditAsync(request.Id, note.Id, "hijacked", Bob, "Bob", ct);

        Assert.Equal(NoteOutcome.NotAuthor, result.Outcome);
        host.Db.ChangeTracker.Clear();
        Assert.Equal("mine", (await host.Db.CertificateNotes.SingleAsync(ct)).Body);
        Assert.Empty(host.Audit.Entries);
    }

    [Fact]
    public async Task Delete_ByTheAuthor_RemovesTheNote_AndAuditsItWithoutTheText()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var note = (await host.Service.AddAsync(request.Id, "to be removed", Alice, "Alice", ct)).Note!;
        host.Audit.Entries.Clear();

        var result = await host.Service.DeleteAsync(request.Id, note.Id, Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.Done, result.Outcome);
        Assert.Empty(await host.Db.CertificateNotes.ToListAsync(ct));
        var (action, detail) = Assert.Single(host.Audit.Entries);
        Assert.Equal("NoteDeleted", action);
        Assert.Contains(note.Id.ToString(), detail);
        Assert.DoesNotContain("removed", detail);
    }

    [Fact]
    public async Task Delete_ByAnotherPerson_IsNotAuthor_AndKeepsTheNote()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var note = (await host.Service.AddAsync(request.Id, "mine", Alice, "Alice", ct)).Note!;

        var result = await host.Service.DeleteAsync(request.Id, note.Id, Bob, "Bob", ct);

        Assert.Equal(NoteOutcome.NotAuthor, result.Outcome);
        Assert.Single(await host.Db.CertificateNotes.ToListAsync(ct));
    }

    [Fact]
    public async Task ANoteAddressedThroughTheWrongRequest_IsNoteNotFound_AndUntouched()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var other = await host.RequestAsync("b.contoso.local");
        var note = (await host.Service.AddAsync(request.Id, "mine", Alice, "Alice", ct)).Note!;

        var edit = await host.Service.EditAsync(other.Id, note.Id, "changed", Alice, "Alice", ct);
        var delete = await host.Service.DeleteAsync(other.Id, note.Id, Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.NoteNotFound, edit.Outcome);
        Assert.Equal(NoteOutcome.NoteNotFound, delete.Outcome);
        host.Db.ChangeTracker.Clear();
        Assert.Equal("mine", (await host.Db.CertificateNotes.SingleAsync(ct)).Body);
    }

    [Fact]
    public async Task Edit_AndDelete_OfAnUnknownNote_AreNoteNotFound()
    {
        var (host, request) = await ArrangeAsync();
        await using var _ = host;

        var edit = await host.Service.EditAsync(request.Id, Guid.NewGuid(), "x", Alice, "Alice", TestContext.Current.CancellationToken);
        var delete = await host.Service.DeleteAsync(request.Id, Guid.NewGuid(), Alice, "Alice", TestContext.Current.CancellationToken);

        Assert.Equal(NoteOutcome.NoteNotFound, edit.Outcome);
        Assert.Equal(NoteOutcome.NoteNotFound, delete.Outcome);
    }

    [Fact]
    public async Task DeletingARequest_DeletesItsNotes_AndOnlyItsNotes()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var other = await host.RequestAsync("b.contoso.local");
        await host.Service.AddAsync(request.Id, "goes away", Alice, "Alice", ct);
        await host.Service.AddAsync(other.Id, "stays", Alice, "Alice", ct);
        var requests = new CertificateRequestService(host.Db, host.Audit, new MetadataTestHost.NoWebhooks(),
            new Qertum.Services.Policies.IssuancePolicyService(host.Db, new Qertum.Services.Policies.IssuancePolicyEvaluator()));

        var deleted = await requests.DeleteAsync(request.Id, "alice", ct);

        Assert.True(deleted);
        var left = Assert.Single(await host.Db.CertificateNotes.AsNoTracking().ToListAsync(ct));
        Assert.Equal("stays", left.Body);
    }

    [Fact]
    public async Task RequestExists_IsTrueForAKnownRequestAndFalseForAnUnknownOne()
    {
        var (host, request) = await ArrangeAsync();
        await using var _ = host;

        Assert.True(await host.Service.RequestExistsAsync(request.Id, TestContext.Current.CancellationToken));
        Assert.False(await host.Service.RequestExistsAsync(Guid.NewGuid(), TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CheckAuthor_SeparatesTheAuthorFromOthers_AndUnknownNotesFromWrongRequests()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var other = await host.RequestAsync("b.contoso.local");
        var note = (await host.Service.AddAsync(request.Id, "mine", Alice, "Alice", ct)).Note!;

        Assert.Equal(NoteOutcome.Done, await host.Service.CheckAuthorAsync(request.Id, note.Id, Alice, ct));
        Assert.Equal(NoteOutcome.NotAuthor, await host.Service.CheckAuthorAsync(request.Id, note.Id, Bob, ct));
        Assert.Equal(NoteOutcome.NoteNotFound, await host.Service.CheckAuthorAsync(request.Id, Guid.NewGuid(), Alice, ct));
        Assert.Equal(NoteOutcome.NoteNotFound, await host.Service.CheckAuthorAsync(other.Id, note.Id, Alice, ct));
    }

    [Fact]
    public async Task Edit_WhenTheNoteIsDeletedBeforeTheSave_IsNoteNotFound_NotAnException()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var note = (await host.Service.AddAsync(request.Id, "first", Alice, "Alice", ct)).Note!;
        host.Racer.Armed = true;

        var result = await host.Service.EditAsync(request.Id, note.Id, "second", Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.NoteNotFound, result.Outcome);
    }

    [Fact]
    public async Task Delete_WhenTheNoteIsAlreadyGoneAtTheSave_IsNoteNotFound_NotAnException()
    {
        var ct = TestContext.Current.CancellationToken;
        var (host, request) = await ArrangeAsync();
        await using var _ = host;
        var note = (await host.Service.AddAsync(request.Id, "first", Alice, "Alice", ct)).Note!;
        host.Racer.Armed = true;

        var result = await host.Service.DeleteAsync(request.Id, note.Id, Alice, "Alice", ct);

        Assert.Equal(NoteOutcome.NoteNotFound, result.Outcome);
    }
}
