using System.CommandLine;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;

namespace Qertum.Cli.Commands;

internal static class PermissionCommands
{
    private const string AdminHint = "managing role permissions needs the admin role";

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("permissions", "Role permission commands (list/set need admin)");
        cmd.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildSet(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildMe(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        return cmd;
    }

    /// <summary>Exactly one of --permission or --clear; null when the arguments are usable.</summary>
    internal static string? ValidateSetArguments(string[]? permissions, bool clear) =>
        (permissions is { Length: > 0 }, clear) switch
        {
            (false, false) => "Pass --permission at least once, or --clear.",
            (true, true) => "Pass either --permission or --clear, not both.",
            _ => null
        };

    private static Command BuildList(Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var cmd = new Command("list",
            "List every role with its granted permissions and when a token carrying it was last seen.\n" +
            "\n" +
            "Reads only; changes nothing. The built-in admin role is shown with '*' (all permissions, including certificates.ca). Also lists roles seen in tokens that hold no permissions.\n" +
            "Needs: the admin role.\n" +
            "Exit codes: 0 listed; 1 not signed in, not admin (403) or the API was unreachable.\n" +
            "Output: a table of role, last seen and permissions; --output json prints the overview contract.\n" +
            "Example: qca permissions list");

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var overview = await CliApi.CreateClient(session).GetRolePermissionsOverviewAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(overview);

                Console.WriteLine($"{"Role",-24}  {"Seen",-24}  Permissions");
                Console.WriteLine(new string('-', 100));
                Console.WriteLine($"{"admin",-24}  {"(built in)",-24}  *");
                foreach (var role in overview.Roles)
                {
                    var seen = role.NeverSeen ? "never"
                        : role.NotSeenRecently ? $"stale (last {role.LastSeenUtc:yyyy-MM-dd})"
                        : $"{role.LastSeenUtc:yyyy-MM-dd}";
                    Console.WriteLine($"{CliApi.Trunc(role.Name, 24),-24}  {seen,-24}  {string.Join(", ", role.Permissions)}");
                }

                if (overview.ObservedWithoutPermissions.Count > 0)
                {
                    Console.WriteLine();
                    Console.WriteLine("Seen without permissions:");
                    foreach (var o in overview.ObservedWithoutPermissions)
                        Console.WriteLine($"  {o.Name}  (last seen {o.LastSeenUtc:yyyy-MM-dd})");
                }

                return 0;
            }, AdminHint);
        });

        return cmd;
    }

    private static Command BuildSet(Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var roleArg = new Argument<string>("role") { Description = "Role name as the identity provider spells it (matching ignores case). Required. The built-in admin role cannot be set." };
        var permissionOpt = new Option<string[]>("--permission")
        {
            Description = "Permission to grant, for example certificates.view, certificates.create, certificates.manage, certificates.ca, settings.edit or policies.publish (see 'qca permissions me' for the full list). Repeat the option or space-separate values. Replaces the role's current set. Required unless --clear is given; cannot be combined with --clear.",
            AllowMultipleArgumentsPerToken = true
        };
        permissionOpt.Aliases.Add("-p");
        var clearOpt = new Option<bool>("--clear") { Description = "Remove every permission from the role. Default: off. Cannot be combined with --permission." };

        var cmd = new Command("set",
            "Replace the permissions granted to a role.\n" +
            "\n" +
            "Replaces the role's whole permission set with exactly what you pass (or removes all with --clear); an unchanged set writes nothing. Changes grants audited as RolePermissionsUpdated. Granting certificates.ca lets the role request and approve CA-capable certificates such as subordinate CAs, so grant it sparingly. This changes grants held by the CA only; role names live in the identity provider.\n" +
            "Needs: the admin role.\n" +
            "Exit codes: 0 saved or no changes; 1 neither or both of --permission and --clear, not signed in, not admin (403), invalid role or permission name (400), or the API was unreachable.\n" +
            "Output: 'granted:' and 'revoked:' lines, or '<role>: no changes'; --output json prints the change contract.\n" +
            "Example: qca permissions set pki-operators --permission certificates.view --permission certificates.create");
        cmd.Arguments.Add(roleArg);
        cmd.Options.Add(permissionOpt);
        cmd.Options.Add(clearOpt);

        cmd.SetAction(async (result, ct) =>
        {
            var permissions = result.GetValue(permissionOpt);
            var clear = result.GetValue(clearOpt);
            if (ValidateSetArguments(permissions, clear) is { } argumentError)
            {
                await Console.Error.WriteLineAsync($"error: {argumentError}");
                return 1;
            }

            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var change = await CliApi.CreateClient(session).SetRolePermissionsAsync(
                    result.GetValue(roleArg)!, clear ? [] : permissions!, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(change);

                if (change.IsNoOp)
                {
                    Console.WriteLine($"{change.Role}: no changes");
                    return 0;
                }

                if (change.Granted.Count > 0) Console.WriteLine($"granted: {string.Join(", ", change.Granted)}");
                if (change.Revoked.Count > 0) Console.WriteLine($"revoked: {string.Join(", ", change.Revoked)}");
                return 0;
            }, AdminHint);
        });

        return cmd;
    }

    private static Command BuildMe(Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var cmd = new Command("me",
            "Show your roles and every permission, marked granted or not.\n" +
            "\n" +
            "Reads only; changes nothing. The list includes certificates.ca, which CA-capable requests and approvals need.\n" +
            "Needs: any signed-in caller (no particular permission).\n" +
            "Exit codes: 0 shown; 1 not signed in or the API was unreachable.\n" +
            "Output: your roles, then one 'yes'/'no' line per permission with its description; --output json prints the access contract.\n" +
            "Example: qca permissions me");

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var me = await CliApi.CreateClient(session).GetMyAccessAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(me);

                Console.WriteLine($"Roles: {(me.Roles.Count == 0 ? "(none)" : string.Join(", ", me.Roles))}{(me.IsAdmin ? "  [administrator]" : "")}");
                Console.WriteLine();
                foreach (var p in me.Permissions)
                    Console.WriteLine($"{(p.Granted ? "yes" : "no "),-4} {p.Name,-22} {p.Description}");
                return 0;
            });
        });

        return cmd;
    }
}
