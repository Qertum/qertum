using System.CommandLine;
using System.Net;
using System.Text.Json;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class WebhookCommands
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    // The server's own catalog (Qertum.Contracts), so a new event or family reaches the CLI with no edit.
    private static readonly string[] Families = Enum.GetNames<WebhookEventFamily>();

    private static readonly string[] AllEvents = [.. WellKnownWebhookEvents.All.Order(StringComparer.Ordinal)];

    private static readonly string EventsByFamily = string.Join("; ",
        Enum.GetValues<WebhookEventFamily>().Select(f =>
            $"{f}: {string.Join(", ", WellKnownWebhookEvents.EventsFor(f).Order(StringComparer.Ordinal))}"));

    private const string ListHelp =
        "List all webhook subscriptions.\n\n" +
        "Read-only. The table shows each webhook's id, name, family, URL, subscribed events ('all' means the whole family) and whether it is enabled. It never prints secrets, but the --output json form does include each webhook's signing secret.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 listed (also when there are none); 1 not signed in, or the call failed (403 means you lack settings.edit).\n" +
        "Output: --output json prints the webhooks as an array, including each secret field; treat it as a secret.\n" +
        "Example: qca webhooks list";

    private const string CreateHelp =
        "Create a webhook subscription.\n\n" +
        "Creates a subscription that POSTs events of one family to --url. Without --event it receives the whole family, including events added later; with one or more -e it receives only those. An event outside the chosen family is refused before anything is sent. The URL must also be allowed by the webhook destination policy (see 'qca webhooks destinations'), otherwise the server refuses it. With --secret, deliveries carry an X-Webhook-Signature header (HMAC-SHA256 of the body).\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 created; 1 not signed in, an event outside the family, the server refused the input, or the call failed (403 means you lack settings.edit).\n" +
        "Output: the new webhook as key/value lines (the secret is not printed); --output json prints the webhook including its secret field.\n" +
        "Example: qca webhooks create --name ops-feed --url https://hooks.example.com/qertum -F CertificateRequest -e Issued -e Revoked";

    private const string UpdateHelp =
        "Update a webhook subscription.\n\n" +
        "Changes only what you pass: every omitted option keeps the webhook's current value. -e replaces the whole event list (there is no option to go back to 'whole family' on an existing webhook; delete and recreate it for that). Changing --family without -e keeps the old events, which the server refuses unless they belong to the new family. --secret \"\" clears the signing secret; omitting --secret keeps it. --enable or --disable sets whether it delivers (neither keeps it as is; if both are given, --disable wins). The URL must be allowed by the webhook destination policy.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 updated; 1 not signed in, no webhook with that id, an event outside the family, the server refused the input, or the call failed (403 means you lack settings.edit).\n" +
        "Output: the updated webhook as key/value lines (the secret is not printed); --output json prints the webhook including its secret field.\n" +
        "Example: qca webhooks update 3f2c9a1e-0000-0000-0000-000000000000 -e Issued --disable";

    private const string DeleteHelp =
        "Delete a webhook subscription.\n\n" +
        "Deletes the subscription, so no new events are delivered to it. Nothing asks for confirmation; use 'update --disable' to keep it.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 deleted; 1 not signed in, no webhook with that id, or the call failed (403 means you lack settings.edit).\n" +
        "Example: qca webhooks delete 3f2c9a1e-0000-0000-0000-000000000000";

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("webhooks", "Manage webhook subscriptions");
        cmd.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildCreate(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildUpdate(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildDelete(apiUrlOption, identityUrlOption, tokenOption));
        cmd.Subcommands.Add(WebhookDestinationCommands.Build(apiUrlOption, identityUrlOption, tokenOption, outputOption));
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
                var webhooks = await CliApi.CreateClient(session).GetWebhooksAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(webhooks);

                if (webhooks.Count == 0) { Console.WriteLine("No webhooks configured."); return 0; }

                Console.WriteLine($"{"ID",-36}  {"Name",-20}  {"Family",-18}  {"URL",-34}  {"Events",-24}  Enabled");
                Console.WriteLine(new string('-', 152));
                foreach (var w in webhooks)
                {
                    var events = FormatEvents(w.EventsJson);
                    Console.WriteLine($"{w.Id,-36}  {CliApi.Trunc(w.Name, 20),-20}  {CliApi.Trunc(w.Family.ToString(), 18),-18}  {CliApi.Trunc(w.Url, 34),-34}  {CliApi.Trunc(events, 24),-24}  {(w.IsEnabled ? "yes" : "no")}");
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
        var nameOpt = new Option<string>("--name") { Description = "Display name of the subscription, up to 200 characters. Required", Required = true };
        nameOpt.Aliases.Add("-n");

        var urlOpt = new Option<string>("--url") { Description = "Absolute http or https URL that receives the POST, up to 2000 characters, no credentials or fragment; {field} placeholders are allowed after the host. Required", Required = true };
        urlOpt.Aliases.Add("-u");

        var familyOpt = new Option<string>("--family")
        {
            Description = $"Event family the webhook receives. Choices: {string.Join(", ", Families)}. Default: CertificateRequest.",
            DefaultValueFactory = _ => nameof(WebhookEventFamily.CertificateRequest)
        };
        familyOpt.Aliases.Add("-F");
        familyOpt.AcceptOnlyFromAmong(Families);

        // The valid set depends on --family, which System.CommandLine cannot express statically, so
        // the union is accepted here and the combination is checked in the action.
        var eventOpt = new Option<string[]>("--event")
        {
            Description = $"Event within --family to subscribe to; repeat for several. Omit to receive the whole family. Valid events by family: {EventsByFamily}",
            AllowMultipleArgumentsPerToken = true
        };
        eventOpt.Aliases.Add("-e");
        eventOpt.AcceptOnlyFromAmong(AllEvents);

        var secretOpt = new Option<string?>("--secret") { Description = "Optional signing secret: deliveries carry an X-Webhook-Signature header (HMAC-SHA256 of the body). Default: none (an empty value is treated as none)" };

        var disabledFlag = new Option<bool>("--disabled") { Description = "Create the webhook disabled, so it delivers nothing until enabled. Default: off (created enabled)" };

        var cmd = new Command("create", CreateHelp);
        cmd.Options.Add(nameOpt);
        cmd.Options.Add(urlOpt);
        cmd.Options.Add(familyOpt);
        cmd.Options.Add(eventOpt);
        cmd.Options.Add(secretOpt);
        cmd.Options.Add(disabledFlag);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var family = Enum.Parse<WebhookEventFamily>(result.GetValue(familyOpt)!);
            var events = result.GetValue(eventOpt) ?? [];
            if (await RefuseStrayEventsAsync(events, family)) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var created = await CliApi.CreateClient(session).CreateWebhookAsync(new SaveWebhookRequest
                {
                    Name = result.GetValue(nameOpt)!,
                    Url = result.GetValue(urlOpt)!,
                    Family = family,
                    Secret = result.GetValue(secretOpt),
                    // An empty array means the whole family, so a family that later gains an event does
                    // not need every webhook updated.
                    EventsJson = JsonSerializer.Serialize(events, JsonWeb),
                    IsEnabled = !result.GetValue(disabledFlag)
                }, ct);

                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(created);
                PrintWebhook(created);
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildUpdate(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var idArg = new Argument<Guid>("id") { Description = "Webhook ID (a GUID, as printed by 'qca webhooks list')" };

        var nameOpt = new Option<string?>("--name") { Description = "New display name, up to 200 characters. Default: keep the current one" };
        nameOpt.Aliases.Add("-n");

        var urlOpt = new Option<string?>("--url") { Description = "New target URL (absolute http or https, up to 2000 characters). Default: keep the current one" };
        urlOpt.Aliases.Add("-u");

        var familyOpt = new Option<string?>("--family")
        {
            Description = $"New event family. Choices: {string.Join(", ", Families)}. Default: keep the current one."
        };
        familyOpt.Aliases.Add("-F");
        familyOpt.AcceptOnlyFromAmong(Families);

        var eventOpt = new Option<string[]>("--event")
        {
            Description = $"Replace the subscribed events with these; repeat for several. Default: keep the current events. Valid events by family: {EventsByFamily}",
            AllowMultipleArgumentsPerToken = true
        };
        eventOpt.Aliases.Add("-e");
        eventOpt.AcceptOnlyFromAmong(AllEvents);

        var secretOpt = new Option<string?>("--secret") { Description = "New signing secret. Pass an empty string (--secret \"\") to clear it; omit to keep the current one" };

        var enableFlag = new Option<bool>("--enable") { Description = "Enable the webhook. Default: off (enabled state unchanged)" };
        var disableFlag = new Option<bool>("--disable") { Description = "Disable the webhook. Default: off (enabled state unchanged); wins if --enable is also given" };

        var cmd = new Command("update", UpdateHelp);
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(nameOpt);
        cmd.Options.Add(urlOpt);
        cmd.Options.Add(familyOpt);
        cmd.Options.Add(eventOpt);
        cmd.Options.Add(secretOpt);
        cmd.Options.Add(enableFlag);
        cmd.Options.Add(disableFlag);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = new WebhookId(result.GetValue(idArg));
            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);

                // Fetched to merge: every option left out keeps the webhook's current value.
                var existing = await client.GetWebhookAsync(id, ct);
                if (existing is null)
                {
                    await Console.Error.WriteLineAsync($"error: webhook {id} not found");
                    return 1;
                }

                var family = result.GetValue(familyOpt) is { } f ? Enum.Parse<WebhookEventFamily>(f) : existing.Family;
                var events = result.GetValue(eventOpt);
                if (await RefuseStrayEventsAsync(events ?? [], family)) return 1;

                var isEnabled = existing.IsEnabled;
                if (result.GetValue(enableFlag)) isEnabled = true;
                if (result.GetValue(disableFlag)) isEnabled = false;

                var updated = await client.UpdateWebhookAsync(id, new SaveWebhookRequest
                {
                    Name = result.GetValue(nameOpt) ?? existing.Name,
                    Url = result.GetValue(urlOpt) ?? existing.Url,
                    Family = family,
                    // null = keep the existing secret, "" = clear it; the API applies the same rule.
                    Secret = result.GetValue(secretOpt),
                    EventsJson = events is { Length: > 0 } ? JsonSerializer.Serialize(events, JsonWeb) : existing.EventsJson,
                    IsEnabled = isEnabled
                }, ct);

                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(updated);
                PrintWebhook(updated);
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
        var idArg = new Argument<Guid>("id") { Description = "Webhook ID (a GUID, as printed by 'qca webhooks list')" };
        var cmd = new Command("delete", DeleteHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = new WebhookId(result.GetValue(idArg));
            return await CliApi.RunAsync(async () =>
            {
                try
                {
                    await CliApi.CreateClient(session).DeleteWebhookAsync(id, ct);
                }
                catch (ApiProblemException ex) when (ex.StatusCode == HttpStatusCode.NotFound)
                {
                    await Console.Error.WriteLineAsync($"error: webhook {id} not found");
                    return 1;
                }

                Console.WriteLine($"deleted  {id}");
                return 0;
            });
        });

        return cmd;
    }

    /// <summary>Refuses events the chosen family does not own, before anything is sent.</summary>
    private static async Task<bool> RefuseStrayEventsAsync(string[] events, WebhookEventFamily family)
    {
        var allowed = WellKnownWebhookEvents.EventsFor(family);
        var strays = events.Where(e => !allowed.Contains(e)).ToArray();
        if (strays.Length == 0) return false;

        await Console.Error.WriteLineAsync(
            $"error: event(s) {string.Join(", ", strays)} do not belong to the {family} family. " +
            $"Valid: {string.Join(", ", allowed.Order(StringComparer.Ordinal))}.");
        return true;
    }

    private static void PrintWebhook(Webhook w)
    {
        Console.WriteLine($"{"id",-16} {w.Id}");
        Console.WriteLine($"{"name",-16} {w.Name}");
        Console.WriteLine($"{"url",-16} {w.Url}");
        Console.WriteLine($"{"family",-16} {w.Family}");
        Console.WriteLine($"{"events",-16} {FormatEvents(w.EventsJson)}");
        Console.WriteLine($"{"enabled",-16} {(w.IsEnabled ? "yes" : "no")}");
    }

    private static string FormatEvents(string? eventsJson)
    {
        if (string.IsNullOrEmpty(eventsJson)) return "-";
        try
        {
            var arr = JsonSerializer.Deserialize<string[]>(eventsJson, JsonWeb);
            // An empty subset is the whole family, not "no events".
            return arr is { Length: > 0 } ? string.Join(", ", arr) : "all";
        }
        catch (JsonException) { return eventsJson; }
    }
}
