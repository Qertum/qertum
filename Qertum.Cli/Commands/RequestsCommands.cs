using System.CommandLine;
using System.Text.Json;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

internal static class RequestsCommands
{
    private static readonly JsonSerializerOptions JsonWeb = new(JsonSerializerDefaults.Web);

    private static readonly Option<bool> WaitOption = new("--wait")
    {
        Description = "After approving, wait until each request is issued, or rejected during issuance, polling as the server's Retry-After hint says. " +
                      "Progress goes to stderr. Ignored with --dry-run. Default: off (return as soon as the request is approved)."
    };

    private static readonly Option<int> WaitTimeoutOption = new("--timeout")
    {
        Description = "With --wait: seconds to wait for each request, 1 to 3600. Default 60.",
        DefaultValueFactory = _ => 60
    };

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var cmd = new Command("requests", "Certificate request management");
        cmd.Subcommands.Add(BuildList(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildCreate(apiUrlOption, identityUrlOption, tokenOption, outputOption));
        cmd.Subcommands.Add(BuildApprove(apiUrlOption, identityUrlOption, tokenOption));
        cmd.Subcommands.Add(BuildDeny(apiUrlOption, identityUrlOption, tokenOption));
        return cmd;
    }

    private const string ApproveHelp =
        "Approve pending certificate requests by id.\n" +
        "\n" +
        "Approves each Pending request so the queue consumer issues it. Changes request state; with --dry-run it changes nothing and prints each verdict from the audited approval preview. With --wait it then waits for issuance, polling as the server's Retry-After hint says; progress goes to stderr.\n" +
        "A request for a CA-capable template (for example SubordinateCA) also needs the certificates.ca permission, and you cannot approve a request you filed unless an admin ran 'qca ca approval set waived'. Refusals are named by the rules 'caPermission' and 'selfApproval'.\n" +
        "Needs: certificates.manage (plus certificates.ca for CA-capable templates); like every certificate-request route it also needs certificates.view.\n" +
        "Exit codes: 0 all approved (or, with --dry-run, all admitted; with --wait, all issued); 1 not signed in, a call failed for at least one id (the others are still processed), or with --wait a request was rejected during issuance; 2 with --dry-run, at least one refused and none failed; 3 with --wait the --timeout passed while a request was still being issued (a failure, code 1, takes precedence).\n" +
        "Output: one line per id (approved, or failed with the reason on stderr); with --wait also issued, or failed/timeout on stderr; --dry-run prints each verdict and its violated rules (it ignores --wait). No JSON output.\n" +
        "Example: qca requests approve 3f2c9a1e-0000-0000-0000-000000000000 --wait --timeout 120";

    private const string DenyHelp =
        "Deny pending certificate requests by id.\n" +
        "\n" +
        "Denies each Pending (or Processing) request: it becomes Rejected, is never issued, and a Pending one can later be deleted. Changes request state; a request in any other status (for example already issued) or one that does not exist is reported as failed 'not found' and makes the exit code 1.\n" +
        "Needs: certificates.manage (and certificates.view, which every certificate-request route requires).\n" +
        "Exit codes: 0 all denied; 1 not signed in or a call failed for at least one id (the others are still processed).\n" +
        "Output: one line per id (denied, or failed with the reason on stderr). No JSON output.\n" +
        "Example: qca requests deny 3f2c9a1e-0000-0000-0000-000000000000";

    private static Command BuildList(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var statusOption = new Option<string>("--status")
        {
            Description = "Which requests to list: pending, approved, processing or all. Default: pending.",
            DefaultValueFactory = _ => "pending"
        };
        statusOption.Aliases.Add("-s");
        statusOption.AcceptOnlyFromAmong("pending", "approved", "processing", "all");

        var pageOption = new Option<int>("--page")
        {
            Description = "Page number, starting at 1. Default: 1.",
            DefaultValueFactory = _ => 1
        };

        var pageSizeOption = new Option<int>("--page-size")
        {
            Description = "Requests per page. Default: 100.",
            DefaultValueFactory = _ => 100
        };

        var cmd = new Command("list",
            "List certificate requests, newest page first, filtered by status.\n" +
            "\n" +
            "Reads only; changes nothing. Filtering is done by the server, so --page and --page-size apply to the filtered list.\n" +
            "Needs: certificates.view.\n" +
            "Exit codes: 0 listed (also when nothing matches); 1 not signed in, a call failed or the API was unreachable.\n" +
            "Output: a table with id, common name, type, algorithm, requester and date; --output json prints the request array of the page.\n" +
            "Example: qca requests list --status approved --page 2");
        cmd.Options.Add(statusOption);
        cmd.Options.Add(pageOption);
        cmd.Options.Add(pageSizeOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var statusFilter = result.GetValue(statusOption)!;
            var page = result.GetValue(pageOption);
            var pageSize = result.GetValue(pageSizeOption);

            // Filtered by the server, never in the CLI: filtering one fetched page silently missed every
            // matching request beyond it (the same defect the Web list pages had).
            CertificateRequestStatus? status = statusFilter switch
            {
                "pending" => CertificateRequestStatus.Pending,
                "approved" => CertificateRequestStatus.Approved,
                "processing" => CertificateRequestStatus.Processing,
                _ => null
            };

            return await CliApi.RunAsync(async () =>
            {
                var paged = await CliApi.CreateClient(session).GetCertificateRequestsAsync(page, pageSize, status, cancellationToken: ct);
                if (result.GetValue(outputOption) == "json") return CliApi.PrintJson(paged.Items);

                if (paged.Items.Count == 0)
                {
                    Console.WriteLine($"No {statusFilter} certificate requests found.");
                    return 0;
                }

                Console.WriteLine(
                    $"{"ID",-36}  {"Common Name",-28}  {"Type",-14}  {"Algorithm",-14}  {"Requested By",-20}  {"Created",-12}");
                Console.WriteLine(new string('-', 136));

                foreach (var item in paged.Items)
                {
                    Console.WriteLine(
                        $"{item.Id,-36}  " +
                        $"{CliApi.Trunc(item.CommonName, 28),-28}  " +
                        $"{CliApi.Trunc(item.Type, 14),-14}  " +
                        $"{AlgorithmLabel(item.KeyAlgorithm),-14}  " +
                        $"{CliApi.Trunc(item.RequestedBy, 20),-20}  " +
                        $"{item.CreatedAtUtc:yyyy-MM-dd}");
                }

                Console.WriteLine();
                Console.WriteLine($"Page {page}/{paged.TotalPages}  ({paged.TotalCount} total)");
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
        var commonNameOption = new Option<string?>("--common-name")
        {
            Description = "X.509 Common Name (CN) for the certificate. Required unless --from-json is used."
        };
        commonNameOption.Aliases.Add("-n");

        var typeOption = new Option<string>("--type")
        {
            Description = "Certificate template type key, for example WebServer or SubordinateCA. Default: WebServer. A CA-capable template needs certificates.ca.",
            DefaultValueFactory = _ => "WebServer"
        };
        typeOption.Aliases.Add("-T");

        var algorithmOption = new Option<string?>("--algorithm")
        {
            Description = "Key algorithm, one of: " + string.Join(", ",
                Enum.GetValues<CertificateKeyAlgorithm>().Select(a => a.ToCanonicalString())) +
                          ". Default: RSA."
        };
        algorithmOption.Aliases.Add("-k");
        algorithmOption.AcceptOnlyFromAmong(
            [.. Enum.GetValues<CertificateKeyAlgorithm>().Select(a => a.ToCanonicalString())]);

        var sanOption = new Option<string[]>("--san")
        {
            Description = "DNS Subject Alternative Name(s) to include; repeat the option or space-separate values: --san foo.com --san *.foo.com. Default: none.",
            AllowMultipleArgumentsPerToken = true,
            Arity = ArgumentArity.ZeroOrMore
        };

        var validityDaysOption = new Option<int?>("--validity-days")
        {
            Description = "Requested validity in days, a whole number. Default: the template's validity, else the CA's default validity. " +
                          "A longer one needs an issuance policy that allows it."
        };

        var dryRunOption = new Option<bool>("--dry-run")
        {
            Description = "Check the request against issuance policy without creating it (nothing is stored). " +
                          "Exit code 2 means it would be rejected. Default: off."
        };

        var fromJsonOption = new Option<string?>("--from-json")
        {
            Description = "Path to a JSON file holding the full request payload, or '-' to read it from stdin; replaces --common-name, --type and the other request options. requestedBy and status in the file are ignored. Default: not used."
        };

        var cmd = new Command("create",
            "Create a certificate request that waits for approval.\n" +
            "\n" +
            "Creates a Pending request; nothing is issued until someone approves it. The requester is always you, taken from your token (requestedBy is never sent). With --dry-run it creates nothing and prints whether issuance policy would accept the request.\n" +
            "A request for a CA-capable template (for example SubordinateCA) also needs the certificates.ca permission; without it the request is refused with the rule 'caPermission'.\n" +
            "Needs: certificates.create (plus certificates.ca for CA-capable templates); like every certificate-request route it also needs certificates.view.\n" +
            "Exit codes: 0 created (or, with --dry-run, would be accepted); 1 not signed in, bad input, a call failed or the request was refused; 2 with --dry-run, would be rejected by policy.\n" +
            "Output: the created request, or with --dry-run the preview verdict; --output json prints that contract. Policy warnings go to stderr.\n" +
            "Example: qca requests create --common-name www.example.com --san www.example.com --type WebServer --dry-run");
        cmd.Options.Add(commonNameOption);
        cmd.Options.Add(typeOption);
        cmd.Options.Add(algorithmOption);
        cmd.Options.Add(sanOption);
        cmd.Options.Add(validityDaysOption);
        cmd.Options.Add(dryRunOption);
        cmd.Options.Add(fromJsonOption);

        cmd.SetAction(async (result, ct) =>
        {
            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            CreateCertificateRequestRequest request;
            var fromJson = result.GetValue(fromJsonOption);
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

                // Read into the API's own request type: a field it does not define (requestedBy, status)
                // is dropped here and never sent — the API takes the requester from the bearer token.
                try
                {
                    request = JsonSerializer.Deserialize<CreateCertificateRequestRequest>(raw, JsonWeb)
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
                var cn = result.GetValue(commonNameOption);
                if (string.IsNullOrWhiteSpace(cn))
                {
                    await Console.Error.WriteLineAsync("error: --common-name is required (or use --from-json <file>)");
                    return 1;
                }

                var sans = result.GetValue(sanOption) ?? [];
                request = new CreateCertificateRequestRequest
                {
                    CommonName = cn,
                    Type = result.GetValue(typeOption)!,
                    PropertiesJson = sans.Length > 0 ? JsonSerializer.Serialize(new { dnsNames = sans }, JsonWeb) : "{}",
                    KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse(result.GetValue(algorithmOption)),
                    ValidityDays = result.GetValue(validityDaysOption),
                };
            }

            var json = result.GetValue(outputOption) == "json";
            return await CliApi.RunAsync(async () =>
            {
                var client = CliApi.CreateClient(session);

                // A dry run asks the preview route, which answers 200 whether or not the request would be
                // accepted — the verdict is in the body. Exit 0 allowed, 2 would be rejected.
                if (result.GetValue(dryRunOption))
                {
                    var preview = await client.PreviewCertificateRequestAsync(request, ct);
                    await CliApi.PrintWarningsAsync(preview.Warnings);
                    if (json)
                    {
                        CliApi.PrintJson(preview);
                        return preview.Allowed ? 0 : 2;
                    }

                    var policy = preview.PolicyName is null ? "none" : $"{preview.PolicyName} v{preview.PolicyVersionNumber}";
                    if (preview.Allowed)
                    {
                        Console.WriteLine("would be accepted");
                        Console.WriteLine($"  Type         : {preview.TemplateTypeKey}");
                        Console.WriteLine($"  Algorithm    : {preview.EffectiveKeyAlgorithm}");
                        Console.WriteLine($"  Validity     : {preview.EffectiveValidityDays} days");
                        Console.WriteLine($"  Policy       : {policy}");
                        return 0;
                    }

                    Console.WriteLine("would be REJECTED");
                    Console.WriteLine($"  Policy       : {policy}");
                    foreach (var violation in preview.Violations)
                        Console.WriteLine($"  - {violation.Rule}: {violation.Message}");
                    return 2;
                }

                var created = await client.QueueCertificateRequestAsync(request, ct);
                await CliApi.PrintWarningsAsync(created.Warnings);
                if (json) return CliApi.PrintJson(created);

                Console.WriteLine($"created   {created.Id}");
                Console.WriteLine($"  Common Name  : {created.CommonName}");
                Console.WriteLine($"  Type         : {created.Type}");
                Console.WriteLine($"  Algorithm    : {AlgorithmLabel(created.KeyAlgorithm)}");
                Console.WriteLine($"  Status       : {created.Status}");
                Console.WriteLine($"  Requested By : {created.RequestedBy}");
                return 0;
            });
        });

        return cmd;
    }

    private static Command BuildApprove(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption)
    {
        var cmd = BuildDecision("approve", ApproveHelp, "approved ",
            apiUrlOption, identityUrlOption, tokenOption,
            (client, id, ct) => client.ApproveAsync(id, ct),
            preflight: result => result.GetValue(WaitOption) ? ApprovalWait.ValidateTimeout(result.GetValue(WaitTimeoutOption)) : null,
            afterDecision: (result, client, approved, ct) => result.GetValue(WaitOption)
                ? ApprovalWait.RunAsync(client, approved, TimeSpan.FromSeconds(result.GetValue(WaitTimeoutOption)), Console.Out, Console.Error, ct)
                : Task.FromResult(0));
        cmd.Options.Add(WaitOption);
        cmd.Options.Add(WaitTimeoutOption);

        var dryRunOption = new Option<bool>("--dry-run")
        {
            Description = "Show whether the current issuance policy admits each request, without approving. " +
                          "Each check is audited. Exit code 2 means at least one would be refused. Default: off (approve for real)."
        };
        cmd.Options.Add(dryRunOption);

        var approve = cmd.Action!;
        var idsArg = (Argument<Guid[]>)cmd.Arguments[0];
        cmd.SetAction(async (result, ct) =>
        {
            if (!result.GetValue(dryRunOption))
                return await ((System.CommandLine.Invocation.AsynchronousCommandLineAction)approve).InvokeAsync(result, ct);

            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var client = CliApi.CreateClient(session);
            var verdicts = new List<bool?>();
            foreach (var id in result.GetValue(idsArg)!)
            {
                try
                {
                    var preview = await client.PreviewApprovalAsync(new CertificateRequestId(id), ct);
                    if (preview is null)
                    {
                        await Console.Error.WriteLineAsync($"failed    {id}  — not found");
                        verdicts.Add(null);
                        continue;
                    }

                    foreach (var line in ApprovalPreviewLines(id, preview))
                        Console.WriteLine(line);
                    verdicts.Add(preview.Allowed);
                }
                catch (Exception ex) when (ex is ApiProblemException or HttpRequestException)
                {
                    await Console.Error.WriteLineAsync($"failed    {id}  — {ex.Message}");
                    verdicts.Add(null);
                }
            }

            return ApprovalDryRunExitCode(verdicts);
        });

        return cmd;
    }

    /// <summary>What <c>approve --dry-run</c> prints for one request's approval preview.</summary>
    internal static IEnumerable<string> ApprovalPreviewLines(Guid id, ApprovalPreviewResponse preview)
    {
        var policy = preview.PolicyName is null ? "none" : $"{preview.PolicyName} v{preview.PolicyVersionNumber}";
        yield return preview.Allowed ? $"admitted  {id}  (policy: {policy})" : $"REFUSED   {id}  (policy: {policy})";
        foreach (var violation in preview.Violations)
            yield return $"  - {violation.Rule}: {violation.Message}";
        if (preview.PolicyChangedSinceEvaluation)
            yield return preview.EvaluatedPolicyVersionNumber is { } created
                ? $"  last evaluated under policy '{preview.EvaluatedPolicyName}' v{created}; the policy has changed since"
                : "  no policy version was recorded when it was last evaluated";
        if (preview.RequesterRolesCheckedAtSubmission)
            yield return "  requester roles are checked at submission, not at approval";
    }

    /// <summary>1 when any check failed, else 2 when any request would be refused, else 0 (as <c>create --dry-run</c>).</summary>
    internal static int ApprovalDryRunExitCode(IEnumerable<bool?> verdicts)
    {
        var list = verdicts.ToList();
        if (list.Any(v => v is null)) return 1;
        return list.Any(v => v == false) ? 2 : 0;
    }

    private static Command BuildDeny(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption) =>
        BuildDecision("deny", DenyHelp, "denied   ",
            apiUrlOption, identityUrlOption, tokenOption,
            (client, id, ct) => client.RejectAsync(id, ct));

    /// <summary>Approve and deny: one call per id, each reported on its own line; exit 1 if any failed.</summary>
    private static Command BuildDecision(
        string name,
        string description,
        string doneLabel,
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Func<CertificateRequestsApiClient, CertificateRequestId, CancellationToken, Task<CertificateRequest?>> decide,
        Func<ParseResult, string?>? preflight = null,
        Func<ParseResult, CertificateRequestsApiClient, CertificateRequest, CancellationToken, Task<int>>? afterDecision = null)
    {
        var idsArg = new Argument<Guid[]>("ids")
        {
            Description = $"One or more certificate request IDs (GUIDs) to {name}, separated by spaces. Required.",
            Arity = ArgumentArity.OneOrMore
        };

        var cmd = new Command(name, description);
        cmd.Arguments.Add(idsArg);

        cmd.SetAction(async (result, ct) =>
        {
            // Before anything is approved: a bad option must not leave half the ids decided.
            if (preflight?.Invoke(result) is { } invalid)
            {
                await Console.Error.WriteLineAsync($"error: {invalid}");
                return 1;
            }

            var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
            if (session is null) return 1;

            var client = CliApi.CreateClient(session);
            var exitCode = 0;
            foreach (var id in result.GetValue(idsArg)!)
            {
                string? failure;
                CertificateRequest? decided = null;
                try
                {
                    decided = await decide(client, new CertificateRequestId(id), ct);
                    failure = decided is null ? "not found" : null;
                }
                catch (ApiProblemException ex)
                {
                    failure = ex.Message;
                }
                catch (HttpRequestException ex)
                {
                    failure = ex.Message;
                }

                if (failure is null)
                {
                    Console.WriteLine($"{doneLabel} {id}");
                    if (afterDecision is not null)
                    {
                        try
                        {
                            exitCode = ApprovalWait.Merge(exitCode, await afterDecision(result, client, decided!, ct));
                        }
                        catch (Exception ex) when (ex is ApiProblemException or HttpRequestException)
                        {
                            await Console.Error.WriteLineAsync($"failed    {id}  — {ex.Message}");
                            exitCode = 1;
                        }
                    }
                }
                else
                {
                    await Console.Error.WriteLineAsync($"failed    {id}  — {failure}");
                    exitCode = 1;
                }
            }

            return exitCode;
        });

        return cmd;
    }

    // A row with no stored algorithm says so rather than guessing RSA.
    private static string AlgorithmLabel(CertificateKeyAlgorithm? algorithm) =>
        algorithm?.ToCanonicalString() ?? CertificateAlgorithmLines.Unknown;
}
