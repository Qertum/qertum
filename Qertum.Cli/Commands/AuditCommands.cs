using System.CommandLine;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;

namespace Qertum.Cli.Commands;

internal static class AuditCommands
{
    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("audit", "Audit log commands (admin only)");
        cmd.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildCheckpoint(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildVerify());
        return cmd;
    }

    private const string ListHelp =
        "List audit log entries, newest first, one page at a time.\n\n" +
        "Reads the CA's audit log; it changes nothing. There is no total count: keep raising --page until a page comes back empty.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 listed (including an empty page); 1 not signed in or the call failed (403 means you are not admin).\n" +
        "Output: --output json prints the array of audit entries for the page.\n" +
        "Example: qca audit list --page 2 --page-size 100";

    private static Command BuildList(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var pageOption = new Option<int>("--page")
        {
            Description = "Page number, starting at 1 (default 1).",
            DefaultValueFactory = _ => 1
        };

        var pageSizeOption = new Option<int>("--page-size")
        {
            Description = "Entries per page (default 50); the server clamps values to 1-500.",
            DefaultValueFactory = _ => 50
        };

        var cmd = new Command("list", ListHelp);
        cmd.Options.Add(pageOption);
        cmd.Options.Add(pageSizeOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var page = result.GetValue(pageOption);
            var pageSize = result.GetValue(pageSizeOption);

            return await CliApi.RunAsync(async () =>
            {
                var entries = await CliApi.CreateClient(session).GetAuditLogAsync(page, pageSize, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(entries);

                if (entries.Count == 0)
                {
                    Console.WriteLine("No audit log entries found.");
                    return 0;
                }

                Console.WriteLine(
                    $"{"Timestamp (UTC)",-20}  {"Action",-20}  {"Performed By",-24}  {"Resource Name",-28}  {"Detail",-30}");
                Console.WriteLine(new string('-', 132));

                foreach (var e in entries)
                {
                    Console.WriteLine(
                        $"{e.OccurredAtUtc,-20:yyyy-MM-dd HH:mm:ss}  " +
                        $"{CliApi.Trunc(e.Action, 20),-20}  " +
                        $"{CliApi.Trunc(e.PerformedBy, 24),-24}  " +
                        $"{CliApi.Trunc(e.ResourceName, 28),-28}  " +
                        $"{CliApi.Trunc(e.Detail, 30),-30}");
                }

                Console.WriteLine();
                Console.WriteLine($"Page {page}  ({entries.Count} entries on this page, page-size {pageSize})");
                return 0;
            });
        });

        return cmd;
    }

    private const string CheckpointHelp =
        "Print the head of every audit hash chain now.\n\n" +
        "Keep the output off this host (a ticket, a vault, the webhook receiver) as the anchor for 'qca audit verify --anchor'; a checkpoint stored on the same volume as the log proves nothing. The AuditCheckpoint webhook carries the same data every hour.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 printed (an empty chains list means nothing is chained yet); 1 not signed in or the call failed (403 means you are not admin).\n" +
        "Output: --output json prints the checkpoint object; save it as the anchor file.\n" +
        "Example: qca audit checkpoint --output json > anchor-2026-10-14.json";

    private static Command BuildCheckpoint(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("checkpoint", CheckpointHelp);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var checkpoint = await CliApi.CreateClient(session).GetAuditCheckpointAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(checkpoint);

                Console.WriteLine($"Generated (UTC): {checkpoint.GeneratedAtUtc:yyyy-MM-dd HH:mm:ss}");
                if (checkpoint.Chains.Count == 0)
                {
                    Console.WriteLine("No chained audit entries yet.");
                    return 0;
                }

                foreach (var head in checkpoint.Chains)
                    Console.WriteLine($"{head.Writer,-28}  seq {head.Seq,-8}  {head.Hash}");
                return 0;
            });
        });

        return cmd;
    }

    private const string VerifyHelp =
        "Verify audit hash chains in copied log files, offline.\n\n" +
        "Reads the files only; it needs no server and no token. Detects an edited, deleted, inserted or swapped entry. A cut tail is detected only with --anchor, a checkpoint kept off-host from before the cut. A log whose oldest files were retained away still verifies from its first line. Restoring a backup rewinds the log, so an anchor taken later reports AnchorBeyondLog.\n" +
        "Needs: read access to the .clef files (the audit-logs directory of the data volume, or a copy).\n" +
        "Exit codes: 0 every chain intact (and the anchor matched); 1 a chain is broken or the anchor does not match; 2 nothing could be read or the anchor file is not valid.\n" +
        "Example: qca audit verify ./audit-logs --anchor anchor-2026-10-14.json";

    private static Command BuildVerify()
    {
        var pathsArgument = new Argument<string[]>("paths")
        {
            Description = "One or more .clef files or directories containing them.",
            Arity = ArgumentArity.OneOrMore
        };
        var anchorOption = new Option<string?>("--anchor")
        {
            Description = "A checkpoint JSON saved from 'qca audit checkpoint --output json', or the heads array of an AuditCheckpoint webhook."
        };

        var cmd = new Command("verify", VerifyHelp);
        cmd.Arguments.Add(pathsArgument);
        cmd.Options.Add(anchorOption);
        cmd.SetAction(result => AuditVerifyRunner.Run(result.GetValue(pathsArgument) ?? [], result.GetValue(anchorOption), Console.Out, Console.Error));
        return cmd;
    }
}
