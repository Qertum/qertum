using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.CertificateNotes;

/// <summary>What an operation on a note came to.</summary>
public enum NoteOutcome
{
    /// <summary>The operation was carried out (an edit to the same text counts: nothing to change).</summary>
    Done,

    /// <summary>No request has that id.</summary>
    RequestNotFound,

    /// <summary>The request has no note with that id (including a note that belongs to another request).</summary>
    NoteNotFound,

    /// <summary>The note exists but the caller is not its author.</summary>
    NotAuthor,

    /// <summary>The request already holds <see cref="CertificateNote.MaxPerRequest"/> notes.</summary>
    TooMany
}

/// <summary>The outcome of a note operation, with the note when there is one.</summary>
/// <param name="Outcome">What happened.</param>
/// <param name="Note">The added or edited note; null otherwise.</param>
public sealed record NoteResult(NoteOutcome Outcome, CertificateNote? Note = null);

/// <summary>Adds, edits and deletes notes. Authors only edit and delete their own; the caller has already passed <c>certificates.view</c>.</summary>
public interface ICertificateNoteService
{
    /// <summary>Adds a note to a request.</summary>
    Task<NoteResult> AddAsync(CertificateRequestId requestId, string body, string authorSubject, string authorName,
        CancellationToken cancellationToken = default);

    /// <summary>Replaces the text of the caller's own note. Editing to the same text changes nothing.</summary>
    Task<NoteResult> EditAsync(CertificateRequestId requestId, NoteId noteId, string body, string callerSubject, string callerName,
        CancellationToken cancellationToken = default);

    /// <summary>Deletes the caller's own note.</summary>
    Task<NoteResult> DeleteAsync(CertificateRequestId requestId, NoteId noteId, string callerSubject, string callerName,
        CancellationToken cancellationToken = default);

    /// <summary>Whether the request exists.</summary>
    Task<bool> RequestExistsAsync(CertificateRequestId requestId, CancellationToken cancellationToken = default);

    /// <summary>
    /// <see cref="NoteOutcome.Done"/> when the caller authored the note, <see cref="NoteOutcome.NotAuthor"/> when someone
    /// else did, <see cref="NoteOutcome.NoteNotFound"/> when the request has no such note. Reads only.
    /// </summary>
    Task<NoteOutcome> CheckAuthorAsync(CertificateRequestId requestId, NoteId noteId, string callerSubject, CancellationToken cancellationToken = default);
}

internal sealed class CertificateNoteService(
    CertificateRequestDbContext db,
    IAuditLogService auditLog,
    TimeProvider? timeProvider = null) : ICertificateNoteService
{
    private readonly TimeProvider _clock = timeProvider ?? TimeProvider.System;

    public async Task<NoteResult> AddAsync(CertificateRequestId requestId, string body, string authorSubject, string authorName,
        CancellationToken cancellationToken = default)
    {
        var commonName = await CommonNameOfAsync(requestId, cancellationToken);
        if (commonName is null) return new NoteResult(NoteOutcome.RequestNotFound);

        if (await db.CertificateNotes.CountAsync(n => n.RequestId == requestId, cancellationToken) >= CertificateNote.MaxPerRequest)
            return new NoteResult(NoteOutcome.TooMany);

        var now = _clock.GetUtcNow().UtcDateTime;
        var note = new CertificateNote
        {
            RequestId = requestId, Body = CertificateNote.NormalizeBody(body), AuthorSubject = authorSubject,
            AuthorName = authorName, CreatedAtUtc = now, UpdatedAtUtc = now
        };
        db.CertificateNotes.Add(note);
        await db.SaveChangesAsync(cancellationToken);

        // The audit entry names the note and never carries its text: the text can be rewritten, the record of the act cannot.
        await auditLog.LogAsync("NoteAdded", authorName, (Guid)requestId, commonName, $"Note {note.Id}", cancellationToken);
        return new NoteResult(NoteOutcome.Done, note);
    }

    public async Task<NoteResult> EditAsync(CertificateRequestId requestId, NoteId noteId, string body, string callerSubject, string callerName,
        CancellationToken cancellationToken = default)
    {
        var note = await db.CertificateNotes.SingleOrDefaultAsync(n => n.Id == noteId && n.RequestId == requestId, cancellationToken);
        if (note is null) return new NoteResult(NoteOutcome.NoteNotFound);
        if (!string.Equals(note.AuthorSubject, callerSubject, StringComparison.Ordinal))
            return new NoteResult(NoteOutcome.NotAuthor);

        var text = CertificateNote.NormalizeBody(body);
        if (string.Equals(note.Body, text, StringComparison.Ordinal)) return new NoteResult(NoteOutcome.Done, note);

        note.Body = text;
        note.UpdatedAtUtc = _clock.GetUtcNow().UtcDateTime;
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            // The note was deleted between reading it and saving: it no longer exists, which is a 404, not a failure.
            db.ChangeTracker.Clear();
            return new NoteResult(NoteOutcome.NoteNotFound);
        }

        await auditLog.LogAsync("NoteEdited", callerName, (Guid)requestId, await CommonNameOfAsync(requestId, cancellationToken),
            $"Note {note.Id}", cancellationToken);
        return new NoteResult(NoteOutcome.Done, note);
    }

    public async Task<NoteResult> DeleteAsync(CertificateRequestId requestId, NoteId noteId, string callerSubject, string callerName,
        CancellationToken cancellationToken = default)
    {
        var note = await db.CertificateNotes.SingleOrDefaultAsync(n => n.Id == noteId && n.RequestId == requestId, cancellationToken);
        if (note is null) return new NoteResult(NoteOutcome.NoteNotFound);
        if (!string.Equals(note.AuthorSubject, callerSubject, StringComparison.Ordinal))
            return new NoteResult(NoteOutcome.NotAuthor);

        db.CertificateNotes.Remove(note);
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            // Already deleted (a double click, a retry): the outcome the caller wanted holds, but there is no such note now.
            db.ChangeTracker.Clear();
            return new NoteResult(NoteOutcome.NoteNotFound);
        }

        await auditLog.LogAsync("NoteDeleted", callerName, (Guid)requestId, await CommonNameOfAsync(requestId, cancellationToken),
            $"Note {note.Id}", cancellationToken);
        return new NoteResult(NoteOutcome.Done);
    }

    public async Task<bool> RequestExistsAsync(CertificateRequestId requestId, CancellationToken cancellationToken = default) =>
        await db.CertificateRequests.AsNoTracking().AnyAsync(r => r.Id == requestId, cancellationToken);

    public async Task<NoteOutcome> CheckAuthorAsync(CertificateRequestId requestId, NoteId noteId, string callerSubject, CancellationToken cancellationToken = default)
    {
        var author = await db.CertificateNotes.AsNoTracking().Where(n => n.Id == noteId && n.RequestId == requestId)
            .Select(n => n.AuthorSubject).FirstOrDefaultAsync(cancellationToken);
        return author is null ? NoteOutcome.NoteNotFound
            : string.Equals(author, callerSubject, StringComparison.Ordinal) ? NoteOutcome.Done : NoteOutcome.NotAuthor;
    }

    private Task<string?> CommonNameOfAsync(CertificateRequestId requestId, CancellationToken ct) =>
        db.CertificateRequests.AsNoTracking().Where(r => r.Id == requestId).Select(r => r.CommonName).FirstOrDefaultAsync(ct);
}
