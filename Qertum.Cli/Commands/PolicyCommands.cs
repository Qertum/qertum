using System.CommandLine;
using System.Text.Json;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary>
/// Issuance policy administration (<c>/v1/issuance-policies</c>): the draft → publish lifecycle that
/// decides what every linked template is allowed to issue. Reads need <c>certificates.view</c>,
/// drafting needs <c>settings.edit</c>, and publishing needs <c>policies.publish</c>.
/// </summary>
internal static class PolicyCommands
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var policies = new Command("policies", "Manage issuance policies");
        policies.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        policies.Subcommands.Add(BuildShow(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        policies.Subcommands.Add(BuildVersions(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        policies.Subcommands.Add(BuildCreate(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        policies.Subcommands.Add(BuildUpdate(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        policies.Subcommands.Add(BuildDraft(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        policies.Subcommands.Add(BuildPublish(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        policies.Subcommands.Add(BuildLifecycle("archive", apiUrlOption, identityUrlOption, tokenOption));
        policies.Subcommands.Add(BuildLifecycle("unarchive", apiUrlOption, identityUrlOption, tokenOption));
        policies.Subcommands.Add(BuildDelete(apiUrlOption, identityUrlOption, tokenOption));
        return policies;
    }

    private static Argument<Guid> IdArgument() =>
        new("id") { Description = "Policy id (GUID, as shown by 'qca policies list')." };

    private static Command BuildList(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var cmd = new Command("list", ListHelp);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var items = await CliApi.CreateClient(session).GetIssuancePoliciesAsync(ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(items);

                if (items.Count == 0)
                {
                    Console.WriteLine("No issuance policies configured.");
                    return 0;
                }

                Console.WriteLine($"{"ID",-36}  {"Name",-28}  {"Published",-9}  {"Draft",-5}  {"Templates",-9}  Archived");
                Console.WriteLine(new string('-', 110));
                foreach (var p in items)
                {
                    Console.WriteLine(
                        $"{p.Id,-36}  {CliApi.Trunc(p.Name, 28),-28}  " +
                        $"{(p.PublishedVersionNumber is int v ? $"v{v}" : "-"),-9}  " +
                        $"{(p.HasDraft ? "yes" : "no"),-5}  {p.LinkedTemplateCount,-9}  {(p.IsArchived ? "yes" : "no")}");
                }
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildShow(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var idArg = IdArgument();
        var cmd = new Command("show", ShowHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var policy = await GetRequiredAsync(CliApi.CreateClient(session), result.GetValue(idArg), ct);
                if (policy is null) return 1;
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(policy);

                Console.WriteLine($"ID:          {policy.Id}");
                Console.WriteLine($"Name:        {policy.Name}");
                Console.WriteLine($"Description: {policy.Description}");
                Console.WriteLine($"Archived:    {(policy.IsArchived ? "yes" : "no")}");
                Console.WriteLine($"Templates:   {(policy.LinkedTemplateTypeKeys.Count == 0 ? "(none)" : string.Join(", ", policy.LinkedTemplateTypeKeys))}");
                Console.WriteLine();
                PrintVersion("Published", policy.Published);
                Console.WriteLine();
                PrintVersion("Draft", policy.Draft);
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildVersions(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var idArg = IdArgument();
        var cmd = new Command("versions", VersionsHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var versions = await CliApi.CreateClient(session)
                    .GetIssuancePolicyVersionsAsync(new IssuancePolicyId(result.GetValue(idArg)), ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(versions);

                Console.WriteLine($"{"Version",-8}  {"Status",-11}  {"Max validity",-12}  Published");
                Console.WriteLine(new string('-', 70));
                foreach (var v in versions)
                {
                    Console.WriteLine(
                        $"v{v.VersionNumber,-7}  {v.Status,-11}  " +
                        $"{(v.MaxValidityDays is int m ? $"{m} days" : "-"),-12}  " +
                        $"{v.PublishedAtUtc?.ToString("u") ?? "-"}");
                }
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildCreate(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var nameOpt = new Option<string?>("--name") { Description = "Policy name, required, at most 100 characters; must not already be used by another policy." };
        nameOpt.Aliases.Add("-n");
        var descriptionOpt = new Option<string?>("--description") { Description = "Optional description, at most 500 characters." };
        descriptionOpt.Aliases.Add("-d");

        var cmd = new Command("create", CreateHelp);
        cmd.Options.Add(nameOpt);
        cmd.Options.Add(descriptionOpt);

        cmd.SetAction(async (result, ct) =>
        {
            var name = result.GetValue(nameOpt);
            if (string.IsNullOrWhiteSpace(name))
            {
                await Console.Error.WriteLineAsync("error: --name is required");
                return 1;
            }

            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var policy = await CliApi.CreateClient(session).CreateIssuancePolicyAsync(
                    new SaveIssuancePolicyRequest { Name = name, Description = result.GetValue(descriptionOpt) }, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(policy);

                Console.WriteLine($"Created policy {policy.Id} ({policy.Name}).");
                Console.WriteLine("Set its rules with 'qca policies draft set', then publish them.");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildUpdate(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var idArg = IdArgument();
        var nameOpt = new Option<string?>("--name") { Description = "New name, at most 100 characters, not used by another policy. Omit to keep the current name." };
        nameOpt.Aliases.Add("-n");
        var descriptionOpt = new Option<string?>("--description") { Description = "New description, at most 500 characters. Omit to keep the current description." };
        descriptionOpt.Aliases.Add("-d");

        var cmd = new Command("update", UpdateHelp);
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(nameOpt);
        cmd.Options.Add(descriptionOpt);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = result.GetValue(idArg);
            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);

                // Name is required by the API, so an update that only changes the description has to
                // carry the current name rather than blanking it.
                var existing = await GetRequiredAsync(client, id, ct);
                if (existing is null) return 1;

                var updated = await client.UpdateIssuancePolicyAsync(new IssuancePolicyId(id), new SaveIssuancePolicyRequest
                {
                    Name = result.GetValue(nameOpt) ?? existing.Name,
                    Description = result.GetValue(descriptionOpt) ?? existing.Description
                }, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(updated);

                Console.WriteLine($"Updated policy {id}.");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildDraft(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var draft = new Command("draft", "Manage a policy's draft rules (set, discard)");

        var setIdArg = IdArgument();
        var dnsOpt = new Option<string[]>("--dns-suffix")
        {
            Description = "Allowed DNS suffix; repeatable (for example --dns-suffix example.com --dns-suffix corp.example). Omit to leave DNS names unrestricted.",
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrMore
        };
        var ipOpt = new Option<string[]>("--ip-range")
        {
            Description = "Allowed CIDR range for IP SANs; repeatable (for example --ip-range 10.0.0.0/8). Omit to leave IP SANs unrestricted.",
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrMore
        };
        var algoOpt = new Option<string[]>("--algorithm")
        {
            Description = "Allowed key algorithm; repeatable. Omit to leave key algorithms unrestricted. One of: " +
                          string.Join(", ", Enum.GetValues<CertificateKeyAlgorithm>().Select(a => a.ToCanonicalString())) + ".",
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrMore
        };
        algoOpt.AcceptOnlyFromAmong([.. Enum.GetValues<CertificateKeyAlgorithm>().Select(a => a.ToCanonicalString())]);
        var maxValidityOpt = new Option<int?>("--max-validity-days")
        {
            Description = "Maximum validity in days (1 or more). Omit for no ceiling."
        };
        var roleOpt = new Option<string[]>("--requester-role")
        {
            Description = "IdP role allowed to submit requests under this policy's templates; repeatable; 'admin' cannot be listed. Omit for any role. ACME, EST and renewals are not role-checked.",
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrMore
        };
        var custodyOpt = new Option<string>("--key-custody")
        {
            Description = "Where the key comes from: 'any' (the CA may generate it) or " +
                          "'require-client-generated' (the request must carry a CSR, so only ACME or EST enrollment qualifies). Default: any, also when the option is omitted.",
            DefaultValueFactory = _ => KeyCustodyValues[0]
        };
        custodyOpt.AcceptOnlyFromAmong(KeyCustodyValues);
        var fromJsonOpt = new Option<string?>("--from-json")
        {
            Description = "Path to a JSON draft payload (a SaveIssuancePolicyDraftRequest, camelCase), or '-' for stdin. When given, every rule option above is ignored and the payload alone sets the rules."
        };

        var set = new Command("set", DraftSetHelp);
        set.Arguments.Add(setIdArg);
        set.Options.Add(dnsOpt);
        set.Options.Add(ipOpt);
        set.Options.Add(algoOpt);
        set.Options.Add(maxValidityOpt);
        set.Options.Add(roleOpt);
        set.Options.Add(custodyOpt);
        set.Options.Add(fromJsonOpt);

        set.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            SaveIssuancePolicyDraftRequest request;
            var fromJson = result.GetValue(fromJsonOpt);
            if (fromJson is not null)
            {
                string raw;
                if (fromJson == "-")
                    raw = await Console.In.ReadToEndAsync(ct);
                else if (!File.Exists(fromJson))
                {
                    await Console.Error.WriteLineAsync($"error: file not found: {fromJson}");
                    return 1;
                }
                else
                    raw = await File.ReadAllTextAsync(fromJson, ct);

                try
                {
                    request = JsonSerializer.Deserialize<SaveIssuancePolicyDraftRequest>(raw, JsonWeb)
                              ?? throw new JsonException("The payload is empty.");
                }
                catch (JsonException ex)
                {
                    await Console.Error.WriteLineAsync($"error: invalid JSON — {ex.Message}");
                    return 1;
                }
            }
            else
            {
                request = DraftFromOptions(result.GetValue(dnsOpt), result.GetValue(ipOpt), result.GetValue(algoOpt),
                    result.GetValue(maxValidityOpt), result.GetValue(roleOpt), result.GetValue(custodyOpt));
            }

            return await CliApi.RunAsync(async () =>
            {
                var policy = await CliApi.CreateClient(session)
                    .SaveIssuancePolicyDraftAsync(new IssuancePolicyId(result.GetValue(setIdArg)), request, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(policy);

                Console.WriteLine("Draft saved. It is not enforced until published.");
                PrintVersion("Draft", policy.Draft);
                return 0;
            });
        });

        var discardIdArg = IdArgument();
        var discard = new Command("discard", DraftDiscardHelp);
        discard.Arguments.Add(discardIdArg);
        discard.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                await CliApi.CreateClient(session).DiscardIssuancePolicyDraftAsync(new IssuancePolicyId(result.GetValue(discardIdArg)), ct);
                Console.WriteLine("Draft discarded.");
                return 0;
            });
        });

        draft.Subcommands.Add(set);
        draft.Subcommands.Add(discard);
        return draft;
    }

    private static Command BuildPublish(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption,
        Option<string?> tokenOption, Option<string> outputOption)
    {
        var idArg = IdArgument();
        var yesOpt = new Option<bool>("--yes") { Description = "Skip the 'Publish these rules? [y/N]' confirmation prompt." };
        yesOpt.Aliases.Add("-y");

        var cmd = new Command("publish", PublishHelp);
        cmd.Arguments.Add(idArg);
        cmd.Options.Add(yesOpt);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var id = result.GetValue(idArg);
            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);
                var policy = await GetRequiredAsync(client, id, ct);
                if (policy is null) return 1;
                if (policy.Draft is null)
                {
                    await Console.Error.WriteLineAsync("error: this policy has no draft to publish");
                    return 1;
                }

                Console.WriteLine($"About to publish for policy '{policy.Name}':");
                PrintVersion("Draft", policy.Draft);
                if (!result.GetValue(yesOpt))
                {
                    Console.Write("Publish these rules? [y/N] ");
                    var answer = Console.ReadLine();
                    if (!string.Equals(answer?.Trim(), "y", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.WriteLine("Aborted.");
                        return 1;
                    }
                }

                // The id and timestamp are the draft exactly as printed above: if someone edits it in
                // between, the API answers 409 instead of publishing rules nobody reviewed.
                var published = await client.PublishIssuancePolicyAsync(new IssuancePolicyId(id), new PublishIssuancePolicyRequest
                {
                    DraftVersionId = policy.Draft.Id,
                    DraftUpdatedAtUtc = policy.Draft.UpdatedAtUtc
                }, ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(published);

                Console.WriteLine($"Published v{published.Published?.VersionNumber}. It is enforced from now on.");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildLifecycle(
        string verb,
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption)
    {
        var idArg = IdArgument();
        var cmd = new Command(verb, verb == "archive" ? ArchiveHelp : UnarchiveHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);
                var id = new IssuancePolicyId(result.GetValue(idArg));
                if (verb == "archive")
                    await client.ArchiveIssuancePolicyAsync(id, ct);
                else
                    await client.UnarchiveIssuancePolicyAsync(id, ct);

                Console.WriteLine($"Policy {verb}d.");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildDelete(
        Option<string?> apiUrlOption, Option<string?> identityUrlOption, Option<string?> tokenOption)
    {
        var idArg = IdArgument();
        var cmd = new Command("delete", DeleteHelp);
        cmd.Arguments.Add(idArg);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            return await CliApi.RunAsync(async () =>
            {
                await CliApi.CreateClient(session).DeleteIssuancePolicyAsync(new IssuancePolicyId(result.GetValue(idArg)), ct);
                Console.WriteLine("Policy deleted.");
                return 0;
            });
        });

        return cmd;
    }

    /// <summary>The policy, or null after printing that it does not exist.</summary>
    private static async Task<IssuancePolicyResponse?> GetRequiredAsync(CertificateRequestsApiClient client, Guid id, CancellationToken ct)
    {
        var policy = await client.GetIssuancePolicyAsync(new IssuancePolicyId(id), ct);
        if (policy is null)
            await Console.Error.WriteLineAsync($"error: no issuance policy with ID {id}.");
        return policy;
    }

    private static void PrintVersion(string label, IssuancePolicyVersionResponse? version)
    {
        if (version is null)
        {
            Console.WriteLine($"{label}: (none)");
            return;
        }

        Console.WriteLine($"{label} v{version.VersionNumber} ({version.Status}):");
        Console.WriteLine($"  DNS suffixes:    {Describe(version.AllowedDnsSuffixes)}");
        Console.WriteLine($"  IP ranges:       {Describe(version.AllowedIpRanges)}");
        Console.WriteLine($"  Key algorithms:  {Describe(version.AllowedKeyAlgorithms)}");
        Console.WriteLine($"  Requester roles: {(version.AllowedRequesterRoles.Count == 0 ? "any role" : string.Join(", ", version.AllowedRequesterRoles))}");
        Console.WriteLine($"  Key custody:     {DescribeCustody(version.KeyCustody)}");
        Console.WriteLine($"  Max validity:    {(version.MaxValidityDays is int m ? $"{m} days" : "no ceiling")}");
    }

    /// <summary>The wire values of <see cref="KeyCustodyMode"/>; the first is the default.</summary>
    internal static readonly string[] KeyCustodyValues = ["any", "require-client-generated"];

    /// <summary>The draft `draft set` sends; every rule is replaced, so an omitted option means unrestricted.</summary>
    internal static SaveIssuancePolicyDraftRequest DraftFromOptions(
        string[]? dns, string[]? ip, string[]? algorithms, int? maxValidityDays, string[]? requesterRoles,
        string? keyCustody) => new()
    {
        AllowedDnsSuffixes = [.. dns ?? []],
        AllowedIpRanges = [.. ip ?? []],
        AllowedKeyAlgorithms = [.. algorithms ?? []],
        MaxValidityDays = maxValidityDays,
        AllowedRequesterRoles = [.. requesterRoles ?? []],
        KeyCustody = ParseKeyCustody(keyCustody)
    };

    private static KeyCustodyMode ParseKeyCustody(string? value) => value switch
    {
        "require-client-generated" => KeyCustodyMode.RequireClientGenerated,
        _ => KeyCustodyMode.Any
    };

    private static string DescribeCustody(KeyCustodyMode custody) => custody switch
    {
        KeyCustodyMode.RequireClientGenerated => "client-generated key required (CSR; ACME or EST only)",
        _ => "CA may generate the key"
    };

    private static string Describe(IReadOnlyList<string>? values) =>
        values is null || values.Count == 0 ? "unrestricted" : string.Join(", ", values);

    private const string ListHelp =
        "List issuance policies.\n\n" +
        "Prints one row per policy: id, name, published version, whether a draft exists, number of linked templates and whether it is archived. Archived policies are included.\n" +
        "Needs: certificates.view.\n" +
        "Exit codes: 0 listed (also when there are none); 1 not signed in or the call failed.\n" +
        "Output: --output json prints the array of policy summaries as camelCase JSON.\n" +
        "Example: qca policies list";

    private const string ShowHelp =
        "Show one policy with its published and draft rules.\n\n" +
        "Prints the policy's name, description, archived flag, linked template keys, then the published version and the draft, each with DNS suffixes, IP ranges, key algorithms, requester roles, key custody and maximum validity. A rule shown as unrestricted allows anything.\n" +
        "Needs: certificates.view.\n" +
        "Exit codes: 0 shown; 1 not signed in, no such policy, or the call failed.\n" +
        "Output: --output json prints the full policy (published version and draft included) as camelCase JSON.\n" +
        "Example: qca policies show 3f2c9a1e-0000-0000-0000-000000000000";

    private const string VersionsHelp =
        "List every version of a policy, newest first.\n\n" +
        "Prints version number, status (Draft, Published or Superseded), maximum validity and publication time for each version the policy has had.\n" +
        "Needs: certificates.view.\n" +
        "Exit codes: 0 listed (an unknown policy id also exits 0, printing only the header or an empty array); 1 not signed in or the call failed.\n" +
        "Output: --output json prints the array of versions as camelCase JSON.\n" +
        "Example: qca policies versions 3f2c9a1e-0000-0000-0000-000000000000";

    private const string CreateHelp =
        "Create an issuance policy with an empty draft that enforces nothing.\n\n" +
        "Creates the policy (version 1, a draft). It is not linked to any template and is not enforced until you set rules with 'qca policies draft set', publish them with 'qca policies publish', and link it to a template. Audited.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 created; 1 --name missing or blank, not signed in, or the call failed (409 when the name is taken, 400 for an invalid name or description).\n" +
        "Output: --output json prints the created policy as camelCase JSON.\n" +
        "Example: qca policies create --name \"Web servers\" --description \"Public TLS names only\"";

    private const string UpdateHelp =
        "Rename a policy or change its description.\n\n" +
        "Changes only the name and description; the rules and versions are untouched. An option you omit keeps its current value (the command reads the policy first). Passing neither option saves the policy unchanged.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 updated; 1 not signed in, no such policy, or the call failed (409 when another policy has that name).\n" +
        "Output: --output json prints the updated policy; otherwise one confirmation line.\n" +
        "Example: qca policies update 3f2c9a1e-0000-0000-0000-000000000000 --name \"Web servers v2\"";

    private const string DraftSetHelp =
        "Create or replace a policy's draft rules; nothing is enforced until you publish.\n\n" +
        "Replaces EVERY rule on the draft wholesale (opening a new draft if there is none): a rule list you omit becomes unrestricted, an omitted --max-validity-days means no ceiling, and an omitted --key-custody means 'any', not 'unchanged'. To keep a rule, pass it again; run 'qca policies show <id>' first to see the current draft. With --from-json the payload alone sets the rules and the rule options are ignored. Changes the draft only; the published version keeps being enforced until 'qca policies publish'.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 draft saved; 1 not signed in, --from-json file missing or invalid JSON, or the call failed (409 when the policy is archived, 400 for an invalid rule).\n" +
        "Output: --output json prints the policy including the new draft; otherwise 'Draft saved' and the draft's rules.\n" +
        "Example: qca policies draft set 3f2c9a1e-0000-0000-0000-000000000000 --dns-suffix example.com --algorithm RSA --max-validity-days 90";

    private const string DraftDiscardHelp =
        "Discard a policy's unpublished draft.\n\n" +
        "Deletes the draft version only; the published version and anything already enforced are unaffected. Audited.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 discarded; 1 not signed in, no such policy, the policy has no draft (409), or the call failed.\n" +
        "Output: one confirmation line; --output json changes nothing.\n" +
        "Example: qca policies draft discard 3f2c9a1e-0000-0000-0000-000000000000";

    private const string PublishHelp =
        "Publish the policy's draft so it is enforced from now on.\n\n" +
        "Reads the policy, prints the draft's rules and, unless --yes is given, asks 'Publish these rules? [y/N]'. It then publishes exactly that draft by sending its version id and last-updated time; if someone changed the draft in between the server answers 409 and nothing is published. Publishes the draft as the new version, supersedes the previous published version, and applies to every template linked to the policy. Audited.\n" +
        "Needs: policies.publish (a separate permission from settings.edit).\n" +
        "Exit codes: 0 published; 1 not signed in, no such policy, no draft, answered no at the prompt, or the call failed (409 draft changed or policy archived, 422 when the maximum validity is below a linked template's default).\n" +
        "Output: the 'About to publish for policy ...' line and the draft's rules are ALWAYS printed to stdout first, even with --output json, so stdout is not pure JSON: with --output json the JSON policy (with the published version) follows the preview; otherwise 'Published vN' does.\n" +
        "Example: qca policies publish 3f2c9a1e-0000-0000-0000-000000000000 --yes";

    private const string ArchiveHelp =
        "Archive a policy so it takes no new drafts and cannot be published.\n\n" +
        "Archives the policy; refused while any template links to it (409), so unlink it first. An archived policy refuses 'draft set' and 'publish' (409) until unarchived. Audited.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 archived; 1 not signed in, no such policy, still linked to a template, or the call failed.\n" +
        "Output: one confirmation line; --output json changes nothing.\n" +
        "Example: qca policies archive 3f2c9a1e-0000-0000-0000-000000000000";

    private const string UnarchiveHelp =
        "Return an archived policy to use.\n\n" +
        "Changes the policy from archived back to active, so drafts and publishing work again. Audited.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 unarchived; 1 not signed in, no such policy, or the call failed.\n" +
        "Output: one confirmation line; --output json changes nothing.\n" +
        "Example: qca policies unarchive 3f2c9a1e-0000-0000-0000-000000000000";

    private const string DeleteHelp =
        "Delete a policy and all its versions.\n\n" +
        "Deletes the policy permanently. Refused (409) while a template links to it, or once any certificate request was allowed under one of its versions; archive it instead in that case. Audited.\n" +
        "Needs: settings.edit.\n" +
        "Exit codes: 0 deleted; 1 not signed in, no such policy, refused as above, or the call failed.\n" +
        "Output: one confirmation line; --output json changes nothing.\n" +
        "Example: qca policies delete 3f2c9a1e-0000-0000-0000-000000000000";
}
