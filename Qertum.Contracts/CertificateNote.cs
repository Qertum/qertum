namespace Qertum.Services;

/// <summary>
/// An administrative note on a certificate request, written by a person and shown in the request's timeline. It can be
/// edited and deleted by its author; no earlier version is kept. Plain text: it is displayed as text, never as markup.
/// </summary>
public sealed class CertificateNote
{
    /// <summary>Longest note, counted after trimming.</summary>
    public const int MaxBodyLength = 2000;

    /// <summary>Most notes one request can hold.</summary>
    public const int MaxPerRequest = 200;

    /// <summary>Note identifier.</summary>
    public NoteId Id { get; set; } = new(Guid.NewGuid());

    /// <summary>The request the note belongs to.</summary>
    public CertificateRequestId RequestId { get; set; }

    /// <summary>The note text, normalized by <see cref="NormalizeBody"/>.</summary>
    public string Body { get; set; } = string.Empty;

    /// <summary>The author's immutable subject; edit and delete are decided on it alone.</summary>
    public string AuthorSubject { get; set; } = string.Empty;

    /// <summary>The author's display name when the note was written.</summary>
    public string AuthorName { get; set; } = string.Empty;

    /// <summary>When the note was written (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>When the note was last edited (UTC); equal to <see cref="CreatedAtUtc"/> until an edit.</summary>
    public DateTime UpdatedAtUtc { get; set; }

    /// <summary>
    /// The stored form of <paramref name="body"/>: trimmed, with a line feed for every line break (CRLF and a lone CR
    /// included: a bare carriage return would move a terminal's cursor to column 0 and overwrite what was printed before it).
    /// </summary>
    public static string NormalizeBody(string body) => body.Trim().Replace("\r\n", "\n").Replace('\r', '\n');
}

/// <summary>Request body for adding or editing a note.</summary>
public sealed class SaveCertificateNoteRequest
{
    /// <summary>The note text.</summary>
    public string Body { get; init; } = string.Empty;
}
