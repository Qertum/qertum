using System.CommandLine;
using System.Net;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary>
/// ACME administration. Currently the external account binding credentials
/// (<c>/v1/acme/external-account-keys</c>), which were previously reachable only from the API and
/// the Settings page — every other admin surface has had CLI parity for a while.
/// </summary>
internal static class AcmeCommands
{
    /// <summary>
    /// The <c>certbot register</c> invocation for a new credential. The MAC key is attached with <c>=</c>: it is
    /// base64url, so it can start with '-', and certbot's parser would read that as an option and refuse the command.
    /// </summary>
    internal static IReadOnlyList<string> CertbotRegisterLines(string kid, string macKey) =>
    [
        "  certbot register --server <acme-directory-url> \\",
        $"    --eab-kid {kid} \\",
        $"    --eab-hmac-key={macKey}"
    ];

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var eab = new Command("eab", "Manage ACME external account binding credentials");
        eab.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        eab.Subcommands.Add(BuildCreate(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        eab.Subcommands.Add(BuildSetEnabled("enable", true, apiUrlOption, identityUrlOption, tokenOption, outputOption));
        eab.Subcommands.Add(BuildSetEnabled("disable", false, apiUrlOption, identityUrlOption, tokenOption, outputOption));
        eab.Subcommands.Add(BuildDelete(apiUrlOption, identityUrlOption, tokenOption));

        var acme = new Command("acme", "Manage the ACME server");
        acme.Subcommands.Add(eab);

        var orders = new Command("orders", "Inspect ACME orders and why they are stuck (needs settings.edit)");
        orders.Subcommands.Add(BuildOrdersList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        orders.Subcommands.Add(BuildOrderShow(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        acme.Subcommands.Add(orders);
        return acme;
    }

    private const string OrdersNeed = "ACME orders need settings.edit";

    private const string OrdersListHelp =
        "List ACME orders, newest first.\n\n" +
        "Read-only. Shows each order's id, status, creation time, names and the category of its last failed attempt; use it to find orders that are stuck, then 'qca acme orders show <id>' for the history.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 listed (also when nothing matches); 1 not signed in, or the call failed (403 means you lack settings.edit).\n" +
        "Output: the table, then a 'Page n/m (total)' line; --output json prints only the page object (items, totalCount, page, pageSize).\n" +
        "Example: qca acme orders list --failing --page-size 20";

    private const string OrderShowHelp =
        "Show one ACME order with its authorizations, challenges and diagnostic history.\n\n" +
        "Read-only. Prints the order's names, status, account and expiry, each authorization with its challenges (attempts and next retry), then the history entries with their hints. Challenge tokens are not shown.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 shown; 1 not signed in, no order with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the order detail (order, authorizations, history).\n" +
        "Example: qca acme orders show 3f2c9a1e-0000-0000-0000-000000000000";

    private const string EabListHelp =
        "List ACME external account binding (EAB) credentials, newest first.\n\n" +
        "Read-only. Shows each credential's id, kid, description, whether it is enabled and which ACME account it is bound to ('(unused)' until its first registration). The MAC key is never listed.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 listed (also when there are none); 1 not signed in, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the credentials as an array (no MAC keys).\n" +
        "Example: qca acme eab list";

    private const string EabCreateHelp =
        "Create an ACME external account binding credential and show its MAC key once.\n\n" +
        "Creates a credential with a random kid and MAC key; one credential binds one ACME account, once. Writes an audit entry (AcmeExternalAccountKeyCreated). The MAC key is stored encrypted and printed only in this response, so it cannot be retrieved later: if it is lost, delete the credential and create another. The text output ends with a 'certbot register --eab-kid ... --eab-hmac-key ...' line to copy.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 created; 1 not signed in, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the credential and the MAC key (macKey); that JSON is the only copy of the key, so treat it as a secret.\n" +
        "Example: qca acme eab create --description \"platform team\"";

    private const string EabEnableHelp =
        "Enable an external account binding credential for new-account registration.\n\n" +
        "Enables the credential so ACME clients may present it to register an account (it still binds only one account). Writes an audit entry (AcmeExternalAccountKeyEnabled).\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 enabled; 1 not signed in, no credential with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the updated credential.\n" +
        "Example: qca acme eab enable 3f2c9a1e-0000-0000-0000-000000000000";

    private const string EabDisableHelp =
        "Disable an external account binding credential so it can no longer register accounts.\n\n" +
        "Disables the credential: a new-account request presenting it is refused with the same answer as for an unknown kid. The credential and its audit history are kept, and it can be enabled again; ACME accounts that already registered with it are not changed. Writes an audit entry (AcmeExternalAccountKeyDisabled).\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 disabled; 1 not signed in, no credential with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the updated credential.\n" +
        "Example: qca acme eab disable 3f2c9a1e-0000-0000-0000-000000000000";

    private const string EabDeleteHelp =
        "Delete an external account binding credential permanently.\n\n" +
        "Deletes the credential and its encrypted MAC key; this cannot be undone and nothing asks for confirmation. Writes an audit entry (AcmeExternalAccountKeyDeleted). Use 'disable' instead to keep the record.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 deleted; 1 not signed in, no credential with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Example: qca acme eab delete 3f2c9a1e-0000-0000-0000-000000000000";

    private static Command BuildOrdersList(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var searchOption = new Option<string?>("--search") { Description = "Optional. A name (substring of the order's identifiers) or a GUID, which matches an account id or an order id. Default: no filter" };
        var failingOption = new Option<bool>("--failing") { Description = "Only orders that are invalid, expired without becoming valid, or have a failed challenge attempt. Default: off (all orders)" };
        var pageOption = new Option<int>("--page") { Description = "Page number, 1-based. Default: 1", DefaultValueFactory = _ => 1 };
        var pageSizeOption = new Option<int>("--page-size") { Description = "Orders per page. Default: 50; the server keeps it between 1 and 200", DefaultValueFactory = _ => 50 };

        var cmd = new Command("list", OrdersListHelp);
        cmd.Options.Add(searchOption);
        cmd.Options.Add(failingOption);
        cmd.Options.Add(pageOption);
        cmd.Options.Add(pageSizeOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var page = await CliApi.CreateClient(session).GetAcmeOrdersAsync(
                    result.GetValue(searchOption), result.GetValue(failingOption),
                    result.GetValue(pageOption), result.GetValue(pageSizeOption), ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(page);

                if (page.Items.Count == 0)
                {
                    Console.WriteLine("No ACME orders match.");
                    return 0;
                }

                Console.WriteLine($"{"ID",-36}  {"Status",-8}  {"Created (UTC)",-16}  {"Names",-32}  Last failure");
                Console.WriteLine(new string('-', 130));
                foreach (var order in page.Items)
                {
                    Console.WriteLine(
                        $"{order.Id,-36}  {order.Status,-8}  {order.CreatedAtUtc:yyyy-MM-dd HH:mm}  " +
                        $"{CliApi.Trunc(string.Join(",", order.Identifiers), 32),-32}  {order.LastFailureCategory ?? "-"}");
                }
                Console.WriteLine();
                var pages = Math.Max(1, (int)Math.Ceiling((double)page.TotalCount / Math.Max(1, page.PageSize)));
                Console.WriteLine($"Page {page.Page}/{pages}  ({page.TotalCount} total)");
                return 0;
            }, OrdersNeed);
        });

        return cmd;
    }

    private static Command BuildOrderShow(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "ACME order ID (a GUID, as printed by 'qca acme orders list')" };

        var cmd = new Command("show", OrderShowHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = result.GetValue(idArg);
            return await CliApi.RunAsync(async () =>
            {
                var detail = await CliApi.CreateClient(session).GetAcmeOrderAsync(id, ct);
                if (detail is null)
                {
                    await Console.Error.WriteLineAsync($"error: no ACME order with ID {id}.");
                    return 1;
                }

                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(detail);

                Console.WriteLine($"{string.Join(", ", detail.Order.Identifiers)}  ({detail.Order.Status})");
                Console.WriteLine($"account {detail.Order.AccountId}; expires {detail.Order.ExpiresAtUtc:yyyy-MM-dd HH:mm} UTC");
                if (detail.Order.CertificateRequestId is { } requestId)
                    Console.WriteLine($"certificate request {requestId}");
                Console.WriteLine();
                foreach (var authorization in detail.Authorizations)
                {
                    Console.WriteLine($"{(authorization.Wildcard ? "*." : "")}{authorization.Identifier}  {authorization.Status}");
                    foreach (var challenge in authorization.Challenges)
                    {
                        Console.WriteLine($"  {challenge.Type,-8} {challenge.Status,-11} attempts {challenge.Attempts}" +
                                          (challenge.NextAttemptAfterUtc is { } next ? $", next {next:HH:mm:ss} UTC" : ""));
                    }
                }
                Console.WriteLine();
                foreach (var entry in detail.History)
                {
                    Console.WriteLine($"{entry.OccurredAtUtc:yyyy-MM-dd HH:mm:ss}  {entry.Action}" +
                                      $"{(entry.Category is null ? "" : $" [{entry.Category}]")}  {entry.Detail}");
                    if (entry.Hint is not null)
                        Console.WriteLine($"                     hint: {entry.Hint}");
                }
                return 0;
            }, OrdersNeed);
        });

        return cmd;
    }

    private static Command BuildList(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("list", EabListHelp);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var keys = await CliApi.CreateClient(session).GetAcmeExternalAccountKeysAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(keys);

                if (keys.Count == 0)
                {
                    Console.WriteLine("No external account keys configured.");
                    return 0;
                }

                Console.WriteLine($"{"ID",-36}  {"KID",-24}  {"Description",-28}  {"Enabled",-7}  Bound to");
                Console.WriteLine(new string('-', 135));
                foreach (var k in keys)
                {
                    // A credential binds to exactly one account, and only once — an unbound one is
                    // still waiting for its first registration.
                    var bound = k.BoundAccountId is null ? "(unused)" : k.BoundAccountId.ToString()!;
                    Console.WriteLine(
                        $"{k.Id,-36}  {CliApi.Trunc(k.Kid, 24),-24}  {CliApi.Trunc(k.Description, 28),-28}  " +
                        $"{(k.IsEnabled ? "yes" : "no"),-7}  {bound}");
                }
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildCreate(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var descriptionOpt = new Option<string?>("--description")
        {
            Description = "Optional. Operator-facing label, e.g. the team the credential is for. Default: none"
        };
        descriptionOpt.Aliases.Add("-d");

        var cmd = new Command("create", EabCreateHelp);
        cmd.Options.Add(descriptionOpt);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var created = await CliApi.CreateClient(session).CreateAcmeExternalAccountKeyAsync(
                    new CreateAcmeExternalAccountKeyRequest(result.GetValue(descriptionOpt)), ct);

                // json output includes the MAC key: this is the only response that carries it, so
                // swallowing it here would make the credential unusable.
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(created);

                Console.WriteLine($"ID:          {created.Credential.Id}");
                Console.WriteLine($"KID:         {created.Credential.Kid}");
                Console.WriteLine($"Description: {created.Credential.Description}");
                Console.WriteLine($"Enabled:     {(created.Credential.IsEnabled ? "yes" : "no")}");
                Console.WriteLine();
                Console.WriteLine($"MAC key:     {created.MacKey}");
                Console.WriteLine();
                Console.WriteLine("This key is stored encrypted and is never shown again. Copy it now;");
                Console.WriteLine("if it is lost, delete this credential and issue another.");
                Console.WriteLine();
                Console.WriteLine("certbot:");
                foreach (var line in CertbotRegisterLines(created.Credential.Kid, created.MacKey))
                    Console.WriteLine(line);
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildSetEnabled(
        string name,
        bool enabled,
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Credential ID (a GUID, as printed by 'qca acme eab list')" };

        var cmd = new Command(name, enabled ? EabEnableHelp : EabDisableHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = result.GetValue(idArg);
            return await CliApi.RunAsync(async () =>
            {
                var updated = await CliApi.CreateClient(session).SetAcmeExternalAccountKeyEnabledAsync(id, enabled, ct);
                if (updated is null)
                {
                    await Console.Error.WriteLineAsync($"error: no external account key with ID {id}.");
                    return 1;
                }

                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(updated);

                Console.WriteLine($"{id} {(enabled ? "enabled" : "disabled")}.");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildDelete(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Credential ID (a GUID, as printed by 'qca acme eab list')" };

        var cmd = new Command("delete", EabDeleteHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = result.GetValue(idArg);
            return await CliApi.RunAsync(async () =>
            {
                try
                {
                    await CliApi.CreateClient(session).DeleteAcmeExternalAccountKeyAsync(id, ct);
                }
                catch (ApiProblemException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
                {
                    await Console.Error.WriteLineAsync($"error: no external account key with ID {id}.");
                    return 1;
                }

                Console.WriteLine($"{id} deleted.");
                return 0;
            });
        });

        return cmd;
    }
}
