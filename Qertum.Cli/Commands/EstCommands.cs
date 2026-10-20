using System.CommandLine;
using System.Net;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary>
/// EST server administration. Currently enrollment credentials (<c>/v1/est/enrollment-credentials</c>).
/// </summary>
internal static class EstCommands
{
    private const string ListHelp =
        "List EST enrollment credentials, newest first.\n\n" +
        "Read-only. Shows each credential's id, username, description and whether it is enabled. Passwords are stored hashed and are never listed.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 listed (also when there are none); 1 not signed in, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the credentials as an array.\n" +
        "Example: qca est credentials list";

    private const string CreateHelp =
        "Create an EST enrollment credential (HTTP Basic username and password for /simpleenroll).\n\n" +
        "Creates the credential with the --password you give; the server stores only a hash, so the password cannot be read back, and it is echoed once in this command's output. If it is lost, delete the credential and create another. Writes an audit entry (EstEnrollmentCredentialCreated).\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 created; 1 not signed in, the server refused the input or a duplicate username (409), or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the credential and the password you set, so treat that output as a secret.\n" +
        "Example: qca est credentials create --username <username> --password <password> --description \"warehouse scanners\"";

    private const string EnableHelp =
        "Enable an EST enrollment credential so it can be used again.\n\n" +
        "Enables the credential for /simpleenroll logins. Writes an audit entry (EstEnrollmentCredentialEnabled).\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 enabled; 1 not signed in, no credential with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the updated credential.\n" +
        "Example: qca est credentials enable 3f2c9a1e-0000-0000-0000-000000000000";

    private const string DisableHelp =
        "Disable an EST enrollment credential without deleting it.\n\n" +
        "Disables the credential: /simpleenroll refuses logins with it (the same 401 as any other failure) and records a refused-login event you can read with 'activity'. The credential and its audit history are kept and it can be enabled again; certificates already issued are not revoked. Writes an audit entry (EstEnrollmentCredentialDisabled).\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 disabled; 1 not signed in, no credential with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the updated credential.\n" +
        "Example: qca est credentials disable 3f2c9a1e-0000-0000-0000-000000000000";

    private const string DeleteHelp =
        "Delete an EST enrollment credential permanently.\n\n" +
        "Deletes the credential; this cannot be undone and nothing asks for confirmation. Certificates already issued are not revoked. Writes an audit entry (EstEnrollmentCredentialDeleted). Use 'disable' instead to keep the record.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 deleted; 1 not signed in, no credential with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Example: qca est credentials delete 3f2c9a1e-0000-0000-0000-000000000000";

    private const string ActivityHelp =
        "Show an EST credential's recorded refused logins and enrollments, newest first.\n\n" +
        "Read-only. Prints each recorded event with its category, detail, related request id and a fixed hint for fixing it; use it to find out why a device cannot enroll. Attempts with an unknown username are not recorded.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 shown (also when nothing is recorded); 1 not signed in, no credential with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Output: the entries, then a 'Page n (total)' line; --output json prints only the page object (items, totalCount, page, pageSize).\n" +
        "Example: qca est credentials activity 3f2c9a1e-0000-0000-0000-000000000000 --page 2";

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var credentials = new Command("credentials", "Manage EST enrollment credentials");
        credentials.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        credentials.Subcommands.Add(BuildCreate(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        credentials.Subcommands.Add(BuildSetEnabled("enable", true, apiUrlOption, identityUrlOption, tokenOption, outputOption));
        credentials.Subcommands.Add(BuildSetEnabled("disable", false, apiUrlOption, identityUrlOption, tokenOption, outputOption));
        credentials.Subcommands.Add(BuildDelete(apiUrlOption, identityUrlOption, tokenOption));
        credentials.Subcommands.Add(BuildActivity(apiUrlOption, identityUrlOption, tokenOption, outputOption));

        var est = new Command("est", "Manage the EST server");
        est.Subcommands.Add(credentials);
        return est;
    }

    private static Command BuildActivity(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Enrollment credential ID (a GUID, as printed by 'qca est credentials list')" };
        var pageOption = new Option<int>("--page") { Description = "Page number, 1-based; 50 entries per page. Default: 1", DefaultValueFactory = _ => 1 };

        var cmd = new Command("activity", ActivityHelp);
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(pageOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = result.GetValue(idArg);
            return await CliApi.RunAsync(async () =>
            {
                var page = await CliApi.CreateClient(session).GetEstCredentialActivityAsync(id, result.GetValue(pageOption), 50, ct);
                if (page is null)
                {
                    await Console.Error.WriteLineAsync($"error: no enrollment credential with ID {id}.");
                    return 1;
                }

                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(page);

                if (page.Items.Count == 0)
                {
                    Console.WriteLine("Nothing recorded for this credential.");
                    return 0;
                }

                foreach (var entry in page.Items)
                {
                    Console.WriteLine($"{entry.OccurredAtUtc:yyyy-MM-dd HH:mm:ss}  {entry.Action}" +
                                      $"{(entry.Category is null ? "" : $" [{entry.Category}]")}  {entry.Detail}" +
                                      $"{(entry.RelatedRequestId is { } requestId ? $"  request {requestId}" : "")}");
                    if (entry.Hint is not null)
                        Console.WriteLine($"                     hint: {entry.Hint}");
                }
                Console.WriteLine();
                Console.WriteLine($"Page {page.Page}  ({page.TotalCount} total)");
                return 0;
            }, "EST credential activity needs settings.edit");
        });

        return cmd;
    }

    private static Command BuildList(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("list", ListHelp);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var creds = await CliApi.CreateClient(session).GetEstEnrollmentCredentialsAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(creds);

                if (creds.Count == 0)
                {
                    Console.WriteLine("No enrollment credentials configured.");
                    return 0;
                }

                Console.WriteLine($"{"ID",-36}  {"Username",-20}  {"Description",-28}  {"Enabled",-7}");
                Console.WriteLine(new string('-', 107));
                foreach (var c in creds)
                {
                    Console.WriteLine(
                        $"{c.Id,-36}  {CliApi.Trunc(c.Username, 20),-20}  {CliApi.Trunc(c.Description, 28),-28}  " +
                        $"{(c.IsEnabled ? "yes" : "no"),-7}");
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
        var usernameOpt = new Option<string>("--username")
        {
            Description = "Username devices present as the HTTP Basic user at /simpleenroll. Required; must be unused (a duplicate fails with 409)",
            Required = true
        };
        usernameOpt.Aliases.Add("-u");

        var passwordOpt = new Option<string>("--password")
        {
            Description = "Password devices present with the username. Required; the server validates it. Visible in your shell history and process list, so prefer a throwaway value you hand to the device owner",
            Required = true
        };
        passwordOpt.Aliases.Add("-p");

        var descriptionOpt = new Option<string?>("--description")
        {
            Description = "Optional. Operator-facing label, e.g. the team the credential is for. Default: none"
        };
        descriptionOpt.Aliases.Add("-d");

        var cmd = new Command("create", CreateHelp);
        cmd.Options.Add(usernameOpt);
        cmd.Options.Add(passwordOpt);
        cmd.Options.Add(descriptionOpt);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var created = await CliApi.CreateClient(session).CreateEstEnrollmentCredentialAsync(
                    new CreateEstEnrollmentCredentialRequest(
                        result.GetValue(usernameOpt)!, result.GetValue(passwordOpt)!, result.GetValue(descriptionOpt)),
                    ct);

                // json output includes the password: this is the only response that carries it, so
                // swallowing it here would make the credential unusable.
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(created);

                Console.WriteLine($"ID:          {created.Credential.Id}");
                Console.WriteLine($"Username:    {created.Credential.Username}");
                Console.WriteLine($"Description: {created.Credential.Description}");
                Console.WriteLine($"Enabled:     {(created.Credential.IsEnabled ? "yes" : "no")}");
                Console.WriteLine();
                Console.WriteLine($"Password:    {created.Password}");
                Console.WriteLine();
                Console.WriteLine("This password is stored hashed and is never shown again. Copy it now;");
                Console.WriteLine("if it is lost, delete this credential and issue another.");
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
        var idArg = new Argument<Guid>("id") { Description = "Credential ID (a GUID, as printed by 'qca est credentials list')" };

        var cmd = new Command(name, enabled ? EnableHelp : DisableHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = result.GetValue(idArg);
            return await CliApi.RunAsync(async () =>
            {
                var updated = await CliApi.CreateClient(session).SetEstEnrollmentCredentialEnabledAsync(id, enabled, ct);
                if (updated is null)
                {
                    await Console.Error.WriteLineAsync($"error: no enrollment credential with ID {id}.");
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
        var idArg = new Argument<Guid>("id") { Description = "Credential ID (a GUID, as printed by 'qca est credentials list')" };

        var cmd = new Command("delete", DeleteHelp);
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
                    await CliApi.CreateClient(session).DeleteEstEnrollmentCredentialAsync(id, ct);
                }
                catch (ApiProblemException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
                {
                    await Console.Error.WriteLineAsync($"error: no enrollment credential with ID {id}.");
                    return 1;
                }

                Console.WriteLine($"{id} deleted.");
                return 0;
            });
        });

        return cmd;
    }
}
