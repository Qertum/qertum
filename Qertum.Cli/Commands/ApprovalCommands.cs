using System.CommandLine;
using System.Globalization;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class ApprovalCommands
{
    private const int PageSize = 100;

    private static readonly string[] Statuses = ["pending", "approved", "denied", "used", "expired"];

    public static Command Build(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var cmd = new Command("approvals", "Two-person approval of sensitive operations");
        cmd.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildRequest(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildDecide("approve", approve: true, apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildDecide("deny", approve: false, apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildSwitch(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        return cmd;
    }

    private static Command BuildList(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var mineOption = new Option<bool>("--mine") { Description = "Only the approvals you asked for. Administrators see everyone's by default." };
        var statusOption = new Option<string?>("--status")
        {
            Description = $"Only this status. Choices: {string.Join(", ", Statuses)}. Default: all."
        };
        statusOption.AcceptOnlyFromAmong(Statuses);

        var cmd = new Command("list",
            "List approval requests for sensitive operations (key export by a non-owner, issuer changes, bulk revoke, policy publish).\n" +
            "Read-only. An administrator sees everyone's requests unless --mine; anyone else sees only their own. A request or an approval whose time ran out reads expired.\n" +
            "Needs: any signed-in caller.\n" +
            "Exit codes: 0 listed; 1 not signed in or a call failed.\n" +
            "Output: one line per request (id, operation, status, requester, target); --output json prints the page object. At most 100 are shown, with the total.\n" +
            "Example: qca approvals list --status pending");
        cmd.Options.Add(mineOption);
        cmd.Options.Add(statusOption);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            ApprovalStatus? status = result.GetValue(statusOption) is { } s ? Enum.Parse<ApprovalStatus>(s, ignoreCase: true) : null;
            var json = result.GetValue(outputOption) == "json";
            return await CliApi.RunAsync(() => RunListAsync(CliApi.CreateClient(session), status, result.GetValue(mineOption), json, Console.Out, Console.Error, ct));
        });
        return cmd;
    }

    private static Command BuildRequest(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var operationArg = new Argument<string>("operation")
        {
            Description = "What you want to do: key-export, pfx-export, issuer-create-intermediate, issuer-install-certificate, issuer-upload-crl, issuer-make-default, issuer-retire, issuer-archive, issuer-delete, issuer-key-export, issuer-pfx-export, bulk-revoke or policy-publish."
        };
        var targetOption = new Option<string?>("--target")
        {
            Description = "The id of what the operation acts on (certificate request, issuer, policy or bulk operation). Not used for issuer-create-intermediate."
        };
        var noteOption = new Option<string?>("--note") { Description = "What you will do and why, plain text, at most 500 characters. The approver reads it." };

        var cmd = new Command("request",
            "Ask a second administrator to approve a sensitive operation before you perform it.\n" +
            "Creates an approval request, an audit entry (ApprovalRequested) and a webhook event. When another administrator approves it you have a limited time window (15 minutes by default) to perform the operation once yourself; nothing runs on approval. You cannot approve your own request.\n" +
            "Needs: the permission the operation itself needs (certificates.manage for bulk-revoke, policies.publish for policy-publish, the admin role for issuer operations, access to the key for key-export and pfx-export).\n" +
            "Exit codes: 0 requested; 1 not signed in, refused (403 not allowed, 404 no such target, 409 one is already open) or a call failed.\n" +
            "Output: the new request's id and status; --output json prints the contract.\n" +
            "Example: qca approvals request bulk-revoke --target 3f1d9c0e-0000-4000-8000-000000000001 --note \"retiring the old issuer's leaves\"");
        cmd.Arguments.Add(operationArg);
        cmd.Options.Add(targetOption);
        cmd.Options.Add(noteOption);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            var json = result.GetValue(outputOption) == "json";
            return await CliApi.RunAsync(async () =>
            {
                var created = await CliApi.CreateClient(session).RequestApprovalAsync(
                    new RequestApprovalRequest(result.GetValue(operationArg)!, result.GetValue(targetOption), result.GetValue(noteOption)), ct);
                if (json) return CliApi.PrintJson(created);
                Console.WriteLine($"requested approval {created.Id} ({created.Operation}, {created.Status})");
                return 0;
            });
        });
        return cmd;
    }

    private static Command BuildDecide(
        string name, bool approve, Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "The approval request's id (see: qca approvals list)." };
        var noteOption = new Option<string?>("--note") { Description = "A note for the requester, plain text, at most 500 characters." };

        var cmd = new Command(name, approve
            ? "Approve a pending request for a sensitive operation.\n" +
              "Approves one request: the requester may then perform that operation once, on that target, within the time window; you do not perform it. Writes an audit entry (ApprovalApproved) and a webhook event. You cannot approve your own request.\n" +
              "Needs: the admin role.\n" +
              "Exit codes: 0 approved; 1 not signed in, refused (403 you are not an administrator or it is your own request, 404 no such request, 409 no longer pending) or a call failed.\n" +
              "Output: the request's id and the end of the window; --output json prints the contract.\n" +
              "Example: qca approvals approve 7e2c6a38-0d4f-4a3e-9d57-0c1c8f0b2a11 --note \"checked the list\""
            : "Deny a pending request for a sensitive operation.\n" +
              "Denies one request; the requester has to ask again. Writes an audit entry (ApprovalDenied) and a webhook event. You cannot deny your own request.\n" +
              "Needs: the admin role.\n" +
              "Exit codes: 0 denied; 1 not signed in, refused (403 you are not an administrator or it is your own request, 404 no such request, 409 no longer pending) or a call failed.\n" +
              "Output: the request's id and status; --output json prints the contract.\n" +
              "Example: qca approvals deny 7e2c6a38-0d4f-4a3e-9d57-0c1c8f0b2a11 --note \"not this week\"");
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(noteOption);
        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            var json = result.GetValue(outputOption) == "json";
            return await CliApi.RunAsync(async () =>
            {
                var decided = await CliApi.CreateClient(session).DecideApprovalAsync(
                    new ApprovalRequestId(result.GetValue(idArg)), approve, result.GetValue(noteOption), ct);
                if (json) return CliApi.PrintJson(decided);
                Console.WriteLine(approve
                    ? $"approved {decided.Id}; {decided.RequestedByName} can use it until {Stamp(decided.GrantExpiresAtUtc)}"
                    : $"denied {decided.Id}");
                return 0;
            }, "deciding an approval needs the admin role");
        });
        return cmd;
    }

    private static Command BuildSwitch(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption, Option<string> outputOption)
    {
        var stateArg = new Argument<string>("state") { Description = "on or off." };
        stateArg.AcceptOnlyFromAmong("on", "off");
        var cmd = new Command("switch",
            "Turn two-person approval of sensitive operations on or off.\n" +
            "Sets the CA-wide switch (off by default) and writes an audit entry (TwoPersonApprovalChanged) and a webhook event. While on, key export by a non-owner, issuer changes, bulk revoke and policy publish each need a second administrator's approval; with only one administrator they cannot be done until it is switched off again. Turning it off needs no approval.\n" +
            "Needs: the admin role (not a grantable permission).\n" +
            "Exit codes: 0 set; 1 unknown state or failed (403 means you are not admin).\n" +
            "Output: --output json prints {\"twoPersonApproval\":\"on\"|\"off\"}.\n" +
            "Example: qca approvals switch on");
        cmd.Arguments.Add(stateArg);
        cmd.SetAction(async (result, ct) =>
        {
            if (!ParseSwitch(result.GetValue(stateArg) ?? "", out var enabled))
            {
                await Console.Error.WriteLineAsync("error: the state must be on or off.");
                return 1;
            }
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var updated = await CliApi.CreateClient(session).SetTwoPersonApprovalAsync(enabled, ct);
                var state = updated.RequireTwoPersonApproval ? "on" : "off";
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(new { twoPersonApproval = state });
                Console.WriteLine($"two-person approval is now {state}");
                return 0;
            }, "changing two-person approval needs the admin role");
        });
        return cmd;
    }

    internal static bool ParseSwitch(string text, out bool enabled)
    {
        enabled = false;
        if (string.Equals(text, "on", StringComparison.OrdinalIgnoreCase)) { enabled = true; return true; }
        return string.Equals(text, "off", StringComparison.OrdinalIgnoreCase);
    }

    internal static async Task<int> RunListAsync(
        CertificateRequestsApiClient client, ApprovalStatus? status, bool mine, bool json,
        TextWriter output, TextWriter error, CancellationToken ct)
    {
        var page = await client.GetApprovalsAsync(status, mine, 1, PageSize, ct);
        if (json) return CliApi.PrintJson(page, output);

        if (page.Items.Count == 0)
        {
            await output.WriteLineAsync("No approvals.");
            return 0;
        }

        foreach (var a in page.Items)
        {
            var window = a.Status == ApprovalStatus.Approved ? $"  use by {Stamp(a.GrantExpiresAtUtc)}" : "";
            await output.WriteLineAsync(
                $"{a.Id}  {CliApi.Trunc(a.Operation, 28),-28}  {a.Status,-8}  {CliApi.Trunc(a.RequestedByName, 20),-20}  {CliApi.Trunc(a.TargetLabel ?? a.TargetId ?? "-", 40)}{window}");
        }
        if (page.TotalCount > page.Items.Count)
            await output.WriteLineAsync($"showing {page.Items.Count} of {page.TotalCount}; narrow with --status or --mine.");
        return 0;
    }

    private static string Stamp(DateTime? utc) =>
        utc?.ToString("yyyy-MM-dd HH:mm'Z'", CultureInfo.InvariantCulture) ?? "-";
}
