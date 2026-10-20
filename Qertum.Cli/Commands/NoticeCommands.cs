using System.CommandLine;
using System.Globalization;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class NoticeCommands
{
    private const int PageSize = 200;

    private static readonly string[] Statuses = ["open", "resolved", "all"];
    private static readonly string[] Kinds = ["expiring", "stalled", "failed"];

    public static Command Build(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var cmd = new Command("notices", "List expiry and renewal notices");
        cmd.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        return cmd;
    }

    private static Command BuildList(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var statusOption = new Option<string>("--status")
        {
            Description = $"Which notices to list. Choices: {string.Join(", ", Statuses)}. Default: open.",
            DefaultValueFactory = _ => "open"
        };
        statusOption.AcceptOnlyFromAmong(Statuses);
        var kindOption = new Option<string?>("--kind")
        {
            Description = $"Only this kind: expiring (nearing expiry, no renewal), stalled (renewal waiting for approval) or failed (renewal rejected). Choices: {string.Join(", ", Kinds)}. Default: all kinds."
        };
        kindOption.AcceptOnlyFromAmong(Kinds);

        var cmd = new Command("list",
            "List the notices raised for certificates nearing expiry and for renewals that stall or fail.\n" +
            "Read-only. A notice closes by itself when its situation ends. The contact is the owner team and email recorded in the certificate's metadata; Unknown when none was recorded.\n" +
            "Needs: certificates.view.\n" +
            "Exit codes: 0 listed; 1 not signed in or a call failed.\n" +
            "Output: one line per notice (certificate, what it says, since when, contact); --output json prints the page object. At most 200 are shown, with the total.\n" +
            "Example: qca notices list --status open --kind expiring");
        cmd.Options.Add(statusOption);
        cmd.Options.Add(kindOption);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            var status = result.GetValue(statusOption) switch
            {
                "resolved" => NoticeStatus.Resolved,
                "all" => (NoticeStatus?)null,
                _ => NoticeStatus.Open
            };
            var kind = result.GetValue(kindOption) switch
            {
                "expiring" => NoticeKind.Expiring,
                "stalled" => NoticeKind.RenewalStalled,
                "failed" => NoticeKind.RenewalFailed,
                _ => (NoticeKind?)null
            };
            var json = result.GetValue(outputOption) == "json";
            return await CliApi.RunAsync(() => RunListAsync(CliApi.CreateClient(session), status, kind, json, Console.Out, Console.Error, ct));
        });
        return cmd;
    }

    internal static async Task<int> RunListAsync(
        CertificateRequestsApiClient client, NoticeStatus? status, NoticeKind? kind, bool json,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        var page = await client.GetNoticesAsync(status, kind, 1, PageSize, ct);
        if (json) return CliApi.PrintJson(page, output);

        var label = status is { } s ? s.ToString().ToLowerInvariant() + " " : "";
        if (page.Items.Count == 0)
        {
            await output.WriteLineAsync($"No {label}notices.");
            return 0;
        }

        foreach (var n in page.Items)
        {
            var name = n.CommonName ?? "(request no longer exists)";
            var since = n.CreatedAtUtc.ToString("yyyy-MM-dd HH:mm'Z'", CultureInfo.InvariantCulture);
            var contact = n.OwnerTeam is null && n.ContactEmail is null
                ? "Unknown"
                : string.Join(" ", new[] { n.OwnerTeam, n.ContactEmail }.Where(v => !string.IsNullOrWhiteSpace(v)));
            await output.WriteLineAsync(
                $"{CliApi.Trunc(name, 32),-32}  {CliApi.Trunc(NoticeDescriptions.Describe(n.Kind, n.Step), 40),-40}  {since}  {contact}");
        }
        if (page.TotalCount > page.Items.Count)
            await output.WriteLineAsync($"showing {page.Items.Count} of {page.TotalCount}; narrow with --status or --kind.");
        return 0;
    }
}
