using System.CommandLine;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class CertMetadataCommands
{
    /// <summary>Appended to a 403: who may edit.</summary>
    internal const string ForbiddenHint =
        "only the certificate's requester, an administrator or a holder of certificates.manage can edit its metadata";

    public static Command Build(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var cmd = new Command("metadata", "Show or set the facts recorded about a certificate");
        cmd.Subcommands.Add(BuildShow(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildSet(apiUrlOption, identityUrlOption, tokenOption));
        return cmd;
    }

    private static Command BuildShow(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID). Required." };
        var cmd = new Command("show",
            "Show the owner team, contact, purpose, target system, ticket reference and compatibility note recorded for a certificate.\n" +
            "Read-only. A field nobody recorded reads Unknown.\n" +
            "Needs: certificates.view.\n" +
            "Exit codes: 0 shown; 1 not signed in, request not found or a call failed.\n" +
            "Output: one line per field; --output json prints the metadata object.\n" +
            "Example: qca cert metadata show 3f2c9a1e-0000-0000-0000-000000000000");
        cmd.Arguments.Add(idArg);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            var id = new CertificateRequestId(result.GetValue(idArg));
            var json = result.GetValue(outputOption) == "json";
            return await CliApi.RunAsync(() => RunShowAsync(CliApi.CreateClient(session), id, json, Console.Out, Console.Error, ct));
        });
        return cmd;
    }

    private static Command BuildSet(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Certificate request ID (GUID). Required." };
        var ownerTeam = new Option<string?>("--owner-team") { Description = "Team that owns the certificate, up to 100 characters. Omit to clear." };
        var contactEmail = new Option<string?>("--contact-email") { Description = "Notification contact, a valid email up to 254 characters; grants no access. Omit to clear." };
        var purpose = new Option<string?>("--purpose") { Description = "What the certificate is for, up to 200 characters. Omit to clear." };
        var targetSystem = new Option<string?>("--target-system") { Description = "System the certificate is deployed to, up to 200 characters. Omit to clear." };
        var ticket = new Option<string?>("--ticket") { Description = "Ticket or change reference, up to 100 characters, plain text. Omit to clear." };
        var compatibilityNote = new Option<string?>("--compatibility-note") { Description = "Known compatibility facts, up to 500 characters. Omit to clear (reads Unknown)." };
        var cmd = new Command("set",
            "Replace the facts recorded about a certificate.\n" +
            "Changes the whole set: every option you leave out is cleared, so run 'qca cert metadata show' first to keep what is there. Allowed in every status, audited, and a renewal starts with a copy. Never put keys or secrets here.\n" +
            "Needs: certificates.view, and either being the requester of the certificate or holding certificates.manage (an administrator always may).\n" +
            "Exit codes: 0 stored; 1 not signed in, request not found, refused or a call failed.\n" +
            "Output: the request id and the stored fields.\n" +
            "Example: qca cert metadata set 3f2c9a1e-0000-0000-0000-000000000000 --owner-team Platform --ticket OPS-4711");
        cmd.Arguments.Add(idArg);
        foreach (var option in new Option[] { ownerTeam, contactEmail, purpose, targetSystem, ticket, compatibilityNote })
            cmd.Options.Add(option);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            var id = new CertificateRequestId(result.GetValue(idArg));
            var metadata = new CertificateMetadata
            {
                OwnerTeam = result.GetValue(ownerTeam), ContactEmail = result.GetValue(contactEmail),
                Purpose = result.GetValue(purpose), TargetSystem = result.GetValue(targetSystem),
                TicketReference = result.GetValue(ticket), CompatibilityNote = result.GetValue(compatibilityNote)
            };
            return await CliApi.RunAsync(
                () => RunSetAsync(CliApi.CreateClient(session), id, metadata, Console.Out, Console.Error, ct), ForbiddenHint);
        });
        return cmd;
    }

    internal static async Task<int> RunShowAsync(
        CertificateRequestsApiClient client, CertificateRequestId id, bool json,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        var request = await client.GetByIdAsync(id, ct);
        if (request is null)
        {
            await error.WriteLineAsync($"error: no certificate request with ID {id}.");
            return 1;
        }
        if (json) return CliApi.PrintJson(request.Metadata, output);
        await WriteFieldsAsync(output, request.Metadata);
        return 0;
    }

    internal static async Task<int> RunSetAsync(
        CertificateRequestsApiClient client, CertificateRequestId id, CertificateMetadata metadata,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        var stored = await client.UpdateCertificateMetadataAsync(id, metadata, ct);
        if (stored is null)
        {
            await error.WriteLineAsync($"error: no certificate request with ID {id}.");
            return 1;
        }
        await output.WriteLineAsync($"updated   {id}");
        await WriteFieldsAsync(output, stored);
        return 0;
    }

    private static async Task WriteFieldsAsync(TextWriter output, CertificateMetadata m)
    {
        static string Show(string? value) => string.IsNullOrEmpty(value) ? "Unknown" : value;
        await output.WriteLineAsync($"  Owner Team         : {Show(m.OwnerTeam)}");
        await output.WriteLineAsync($"  Contact Email      : {Show(m.ContactEmail)}");
        await output.WriteLineAsync($"  Purpose            : {Show(m.Purpose)}");
        await output.WriteLineAsync($"  Target System      : {Show(m.TargetSystem)}");
        await output.WriteLineAsync($"  Ticket Reference   : {Show(m.TicketReference)}");
        await output.WriteLineAsync($"  Compatibility Note : {Show(m.CompatibilityNote)}");
    }
}
