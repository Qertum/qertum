using System.CommandLine;
using System.Net;
using System.Net.Sockets;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class WebhookDestinationCommands
{
    private const string ListHelp =
        "Show the effective webhook destination mode and the exact-origin rules.\n\n" +
        "Read-only. Prints 'Public destinations: <AnyPublic|ListedPublic>' and one line per rule: id, enabled or disabled, source (Configuration or Admin), kind (Public or Internal), origin as scheme://host:port and any pinned IP addresses.\n" +
        "Needs: the admin role (reads included; not a grantable permission).\n" +
        "Exit codes: 0 shown; 1 not signed in, or the call failed (403 means you are not admin).\n" +
        "Output: --output json prints the policy (initialized, publicMode, rules) instead of the lines above.\n" +
        "Example: qca webhooks destinations list";

    private const string ModeHelp =
        "Set the public webhook destination mode, or go back to the configured default.\n\n" +
        "any-public lets webhooks target any public HTTP(S) destination; listed-public only the public origins listed as rules; default drops the administrator override so the JSON configuration value applies again (type it lowercase). Changes the mode and writes an audit entry (WebhookDestinationModeUpdated); setting the mode it already has changes and records nothing. Internal origins always need an exact rule with pinned IPs, whatever the mode.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 set; 1 unknown mode, not signed in, or the call failed (403 means you are not admin).\n" +
        "Output: prints 'Public destinations: <mode>' with the mode now in effect.\n" +
        "Example: qca webhooks destinations mode listed-public";

    private const string AddHelp =
        "Add an administrator-owned exact-origin destination rule.\n\n" +
        "Creates an enabled rule for one scheme, host and port. A public origin needs --public and no --ip; an internal origin needs at least one --ip, and its DNS answers must match those addresses exactly (CIDR ranges are not accepted). The URL must be a bare origin: no path, query, credentials or fragment. Writes an audit entry (WebhookDestinationRuleAdded); an identical existing rule is refused with 409.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 added; 1 invalid --url/--ip/--public combination, not signed in, or the call failed (403 means you are not admin).\n" +
        "Output: prints 'added  <rule id>  <scheme>://<host>:<port>'.\n" +
        "Example: qca webhooks destinations add --url https://hooks.internal.example:8443 --ip 10.0.4.12";

    private const string EnableHelp =
        "Enable a webhook destination rule.\n\n" +
        "Enables the rule so webhooks may target its origin again; works on both configuration and administrator rules (an override on a configuration rule, which a JSON reload does not erase). Writes an audit entry (WebhookDestinationRuleToggled).\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 enabled; 1 not signed in, no rule with that id, or the call failed (403 means you are not admin).\n" +
        "Output: prints 'enabled  <rule id>'.\n" +
        "Example: qca webhooks destinations enable 3f2c9a1e-0000-0000-0000-000000000000";

    private const string DisableHelp =
        "Disable a webhook destination rule without deleting it.\n\n" +
        "Disables the rule so webhooks can no longer target its origin through it; works on both configuration and administrator rules and can be reversed with 'enable'. Writes an audit entry (WebhookDestinationRuleToggled).\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 disabled; 1 not signed in, no rule with that id, or the call failed (403 means you are not admin).\n" +
        "Output: prints 'disabled  <rule id>'.\n" +
        "Example: qca webhooks destinations disable 3f2c9a1e-0000-0000-0000-000000000000";

    private const string DeleteHelp =
        "Delete an administrator-owned destination rule.\n\n" +
        "Deletes the rule permanently; nothing asks for confirmation. Only rules whose source is Admin can be deleted: a rule from the JSON configuration is refused with 409, and should be disabled here or removed from the configuration. Writes an audit entry (WebhookDestinationRuleDeleted).\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 deleted; 1 not signed in, no rule with that id, a configuration rule (409), or the call failed (403 means you are not admin).\n" +
        "Output: prints 'deleted  <rule id>'.\n" +
        "Example: qca webhooks destinations delete 3f2c9a1e-0000-0000-0000-000000000000";

    public static Command Build(Option<string?> apiUrl, Option<string?> identityUrl,
        Option<string?> token, Option<string> output)
    {
        var command = new Command("destinations", "Manage allowed webhook destinations");
        command.Subcommands.Add(BuildList(apiUrl, identityUrl, token, output));
        command.Subcommands.Add(BuildMode(apiUrl, identityUrl, token));
        command.Subcommands.Add(BuildAdd(apiUrl, identityUrl, token));
        command.Subcommands.Add(BuildToggle("enable", true, apiUrl, identityUrl, token));
        command.Subcommands.Add(BuildToggle("disable", false, apiUrl, identityUrl, token));
        command.Subcommands.Add(BuildDelete(apiUrl, identityUrl, token));
        return command;
    }

    internal static Command BuildList(Option<string?> apiUrl, Option<string?> identityUrl,
        Option<string?> token, Option<string> output)
    {
        var command = new Command("list", ListHelp);
        command.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, token, apiUrl, identityUrl, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var policy = await CliApi.CreateClient(session).GetWebhookDestinationPolicyAsync(ct);
                if (result.GetValue(output) == "json") return CliApi.PrintJson(policy);
                Console.WriteLine($"Public destinations: {policy.PublicMode}");
                foreach (var rule in policy.Rules)
                {
                    var origin = $"{rule.Scheme}://{(rule.Host.Contains(':') ? $"[{rule.Host}]" : rule.Host)}:{rule.Port}";
                    Console.WriteLine($"{rule.Id}  {(rule.Enabled ? "enabled " : "disabled")}  {rule.Source,-13}  {rule.Kind,-8}  {origin}  {string.Join(", ", rule.AllowedIpAddresses)}");
                }
                return 0;
            }, "admin role required");
        });
        return command;
    }

    internal static Command BuildMode(Option<string?> apiUrl, Option<string?> identityUrl, Option<string?> token)
    {
        var modeArgument = new Argument<string>("mode") { Description = "any-public (any public destination), listed-public (only listed public origins) or default (drop the override; the JSON configuration applies). Case-insensitive except default, which must be lowercase" };
        var command = new Command("mode", ModeHelp);
        command.Arguments.Add(modeArgument);
        command.SetAction(async (result, ct) =>
        {
            var mode = result.GetValue(modeArgument)?.ToLowerInvariant() switch
            {
                "any-public" => WebhookPublicMode.AnyPublic,
                "listed-public" => WebhookPublicMode.ListedPublic,
                "default" => (WebhookPublicMode?)null,
                _ => null
            };
            if (mode is null && result.GetValue(modeArgument) != "default")
            {
                await Console.Error.WriteLineAsync("error: mode must be any-public, listed-public, or default");
                return 1;
            }
            var session = await SessionResolver.ResolveAsync(result, token, apiUrl, identityUrl, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var policy = await CliApi.CreateClient(session).SetWebhookDestinationPublicModeAsync(mode, ct);
                Console.WriteLine($"Public destinations: {policy.PublicMode}");
                return 0;
            }, "admin role required");
        });
        return command;
    }

    internal static Command BuildAdd(Option<string?> apiUrl, Option<string?> identityUrl, Option<string?> token)
    {
        var url = new Option<string>("--url") { Description = "Exact HTTP or HTTPS origin, e.g. https://hooks.example.com or http://10.0.4.12:8080: no path, query, credentials or fragment. Required", Required = true };
        var ips = new Option<string[]>("--ip") { Description = "Exact IP address an internal origin may resolve to; repeat for several. Required unless --public; no CIDR ranges or IPv6 scope ids", AllowMultipleArgumentsPerToken = true };
        var publicFlag = new Option<bool>("--public") { Description = "The origin is public (its DNS answers must all be public addresses), so no IP pins; cannot be combined with --ip. Default: off (an internal rule)" };
        var command = new Command("add", AddHelp);
        command.Options.Add(url);
        command.Options.Add(ips);
        command.Options.Add(publicFlag);
        command.SetAction(async (result, ct) =>
        {
            if (!TryBuildRule(result.GetValue(url), result.GetValue(ips) ?? [], result.GetValue(publicFlag),
                    out var request, out var error))
            {
                await Console.Error.WriteLineAsync($"error: {error}");
                return 1;
            }
            var session = await SessionResolver.ResolveAsync(result, token, apiUrl, identityUrl, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var rule = await CliApi.CreateClient(session).AddWebhookDestinationRuleAsync(request!, ct);
                Console.WriteLine($"added  {rule.Id}  {rule.Scheme}://{rule.Host}:{rule.Port}");
                return 0;
            }, "admin role required");
        });
        return command;
    }

    internal static bool TryBuildRule(string? rawUrl, IReadOnlyList<string> rawIps, bool isPublic,
        out SaveWebhookDestinationRuleRequest? request, out string? error)
    {
        request = null;
        error = "--url must name an exact HTTP(S) origin without path, query, credentials, or fragment";
        if (string.IsNullOrWhiteSpace(rawUrl) || rawUrl != rawUrl.Trim() || rawUrl.Contains('\\') ||
            !Uri.TryCreate(rawUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https") || string.IsNullOrEmpty(uri.Host) ||
            !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment) ||
            !string.IsNullOrEmpty(uri.Query) || uri.AbsolutePath != "/" ||
            rawUrl.Contains('@') || rawUrl.Contains('%') || rawUrl.Contains('{') || rawUrl.Contains('}')) return false;

        if (isPublic && rawIps.Count != 0)
        {
            error = "--public cannot be combined with --ip";
            return false;
        }
        if (!isPublic && rawIps.Count == 0)
        {
            error = "internal destinations require at least one --ip";
            return false;
        }
        foreach (var rawIp in rawIps)
        {
            if (!IPAddress.TryParse(rawIp, out var address) ||
                address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0)
            {
                error = "--ip must be an exact IP address; CIDR ranges are not accepted";
                return false;
            }
        }

        request = new SaveWebhookDestinationRuleRequest
        {
            Kind = isPublic ? WebhookDestinationRuleKind.Public : WebhookDestinationRuleKind.Internal,
            Scheme = uri.Scheme, Host = uri.IdnHost.TrimEnd('.').ToLowerInvariant(), Port = uri.Port,
            AllowedIpAddresses = [.. rawIps]
        };
        error = null;
        return true;
    }

    private static Command BuildToggle(string name, bool enabled, Option<string?> apiUrl,
        Option<string?> identityUrl, Option<string?> token)
    {
        var id = new Argument<Guid>("id") { Description = "Destination rule ID (a GUID, as printed by 'qca webhooks destinations list')" };
        var command = new Command(name, enabled ? EnableHelp : DisableHelp);
        command.Arguments.Add(id);
        command.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, token, apiUrl, identityUrl, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                var rule = await CliApi.CreateClient(session).SetWebhookDestinationRuleEnabledAsync(
                    result.GetValue(id), enabled, ct);
                if (rule is null)
                {
                    await Console.Error.WriteLineAsync("error: destination rule not found");
                    return 1;
                }
                Console.WriteLine($"{name}d  {rule.Id}");
                return 0;
            }, "admin role required");
        });
        return command;
    }

    private static Command BuildDelete(Option<string?> apiUrl, Option<string?> identityUrl, Option<string?> token)
    {
        var id = new Argument<Guid>("id") { Description = "ID of an administrator-owned (Admin source) rule, as printed by 'qca webhooks destinations list'" };
        var command = new Command("delete", DeleteHelp);
        command.Arguments.Add(id);
        command.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, token, apiUrl, identityUrl, ct);
            if (session is null) return 1;
            return await CliApi.RunAsync(async () =>
            {
                await CliApi.CreateClient(session).DeleteWebhookDestinationRuleAsync(result.GetValue(id), ct);
                Console.WriteLine($"deleted  {result.GetValue(id)}");
                return 0;
            }, "admin role required");
        });
        return command;
    }
}
