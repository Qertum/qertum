using System.CommandLine;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class CertNoteCommands
{
    /// <summary>Appended to a 403: only the author changes a note.</summary>
    internal const string ForbiddenHint = "only the author of a note can edit or delete it";

    public static Command Build(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption)
    {
        var cmd = new Command("note", "Add, edit or delete administrative notes on a certificate request");
        cmd.Subcommands.Add(BuildAdd(apiUrlOption, identityUrlOption, tokenOption));
        cmd.Subcommands.Add(BuildEdit(apiUrlOption, identityUrlOption, tokenOption));
        cmd.Subcommands.Add(BuildDelete(apiUrlOption, identityUrlOption, tokenOption));
        return cmd;
    }

    private static Option<string> TextOption(string what) =>
        new("--text") { Description = $"{what} Plain text up to {CertificateNote.MaxBodyLength} characters; line breaks and tabs are allowed. Required", Required = true };

    private static Command BuildAdd(Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID). Required." };
        var text = TextOption("The note.");
        var cmd = new Command("add",
            "Add an administrative note to a certificate request.\n" +
            "Changes the request's history: the note appears in its timeline (qca cert history) for everyone who can view certificates, and the add is audited without the text. A request holds at most 200 notes. Never put keys or secrets in a note.\n" +
            "Needs: certificates.view, and a token that carries a subject.\n" +
            "Exit codes: 0 added; 1 not signed in, request not found, refused or a call failed.\n" +
            "Output: the note id, which edit and delete take.\n" +
            "Example: qca cert note add 3f2c9a1e-0000-0000-0000-000000000000 --text \"Renewed after the outage, see OPS-4711\"");
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(text);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(() => RunAddAsync(CliApi.CreateClient(session), result.GetValue(idArg), result.GetValue(text)!, Console.Out, Console.Error, ct), ForbiddenHint);
        });
        return cmd;
    }

    private static Command BuildEdit(Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID). Required." };
        var noteArg = new Argument<Guid>("note-id") { Description = "Note ID (GUID), shown by 'qca cert history'. Required." };
        var text = TextOption("The new text; it replaces the old text and no earlier version is kept.");
        var cmd = new Command("edit",
            "Replace the text of one of your own notes.\n" +
            "Changes the note: no earlier version is kept, and the timeline marks it edited. Only the author can edit a note, administrators included. Editing to the same text changes nothing.\n" +
            "Needs: certificates.view, and being the note's author.\n" +
            "Exit codes: 0 edited; 1 not signed in, no such note, not the author or a call failed.\n" +
            "Output: the note id.\n" +
            "Example: qca cert note edit 3f2c9a1e-0000-0000-0000-000000000000 4a4a4a4a-0000-0000-0000-000000000000 --text \"Corrected ticket: OPS-4712\"");
        cmd.Arguments.Add(idArg);
        cmd.Arguments.Add(noteArg);
        cmd.Options.Add(text);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(() => RunEditAsync(CliApi.CreateClient(session), result.GetValue(idArg), new NoteId(result.GetValue(noteArg)), result.GetValue(text)!, Console.Out, Console.Error, ct), ForbiddenHint);
        });
        return cmd;
    }

    private static Command BuildDelete(Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID). Required." };
        var noteArg = new Argument<Guid>("note-id") { Description = "Note ID (GUID), shown by 'qca cert history'. Required." };
        var cmd = new Command("delete",
            "Delete one of your own notes.\n" +
            "Deletes the note for good (no earlier version is kept); the timeline keeps a 'NoteDeleted' line without the text. Only the author can delete a note, administrators included.\n" +
            "Needs: certificates.view, and being the note's author.\n" +
            "Exit codes: 0 deleted; 1 not signed in, no such note, not the author or a call failed.\n" +
            "Output: a confirmation line.\n" +
            "Example: qca cert note delete 3f2c9a1e-0000-0000-0000-000000000000 4a4a4a4a-0000-0000-0000-000000000000");
        cmd.Arguments.Add(idArg);
        cmd.Arguments.Add(noteArg);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(() => RunDeleteAsync(CliApi.CreateClient(session), result.GetValue(idArg), new NoteId(result.GetValue(noteArg)), Console.Out, Console.Error, ct), ForbiddenHint);
        });
        return cmd;
    }

    internal static async Task<int> RunAddAsync(CertificateRequestsApiClient client, Guid requestId, string text,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        var note = await client.AddNoteAsync(requestId, text, ct);
        await output.WriteLineAsync($"added   {note.Id}");
        return 0;
    }

    internal static async Task<int> RunEditAsync(CertificateRequestsApiClient client, Guid requestId, NoteId noteId, string text,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        var note = await client.EditNoteAsync(requestId, noteId, text, ct);
        if (note is null)
        {
            await error.WriteLineAsync($"error: no such note {noteId} on request {requestId}.");
            return 1;
        }
        await output.WriteLineAsync($"edited  {note.Id}");
        return 0;
    }

    internal static async Task<int> RunDeleteAsync(CertificateRequestsApiClient client, Guid requestId, NoteId noteId,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        if (!await client.DeleteNoteAsync(requestId, noteId, ct))
        {
            await error.WriteLineAsync($"error: no such note {noteId} on request {requestId}.");
            return 1;
        }
        await output.WriteLineAsync($"deleted {noteId}");
        return 0;
    }

    /// <summary>One line for <c>qca cert history</c>: the note id (what edit and delete take), the marker and the text on a single line.</summary>
    internal static string DescribeForHistory(TimelineEntry entry) =>
        $"[note {entry.NoteId}]{(entry.Edited ? " (edited)" : "")} " + (entry.Detail ?? "").Replace("\r\n", "\n").Replace('\r', '\n').Replace("\n", " / ");
}
