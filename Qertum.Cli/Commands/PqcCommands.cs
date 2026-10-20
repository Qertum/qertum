using System.CommandLine;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary>
/// <c>qca pqc</c>: the CA-wide PQC stage, per-template overrides, and time-limited exceptions.
/// Every action needs the admin role: loosening enforcement is not a grantable permission.
/// </summary>
internal static class PqcCommands
{
    internal const string AdminHint = "managing PQC enforcement needs the admin role";

    // Shared by the parser and BuildCreateRequest so both see the same option instances.
    private static readonly Option<string> TemplateOption = new("--template") { Description = "Template type key the exception applies to, e.g. WebServer (required; must name an existing template, else 404).", Required = true };
    private static readonly Option<string> NameOption = new("--name") { Description = "Exact DNS name or DNS suffix the exception covers, e.g. legacy.example.com (required; no wildcards, no IP addresses).", Required = true };
    private static readonly Option<string> FamilyOption = new("--family") { Description = "Classical key family admitted: rsa or ecdsa (required, case-insensitive).", Required = true };
    private static readonly Option<int> DaysOption = new("--days") { Description = "How long the exception lasts in days (required): 1 to 3650 here; the server refuses more than its PqcExceptions:MaxDays (365 as shipped) with 400.", Required = true };
    private static readonly Option<string> ReasonOption = new("--reason") { Description = "Why the exception is granted (required, at most 500 characters; kept in the audit entry).", Required = true };

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var pqc = new Command("pqc", "Post-quantum enforcement: stage, template overrides, exceptions (admin only)");

        Command Sub(Command parent, string name, string description, Func<ParseResult, CertificateRequestsApiClient, CancellationToken, Task<int>> run,
            params Symbol[] symbols) => SubWithHint(parent, name, description, run, AdminHint, symbols);

        Command SubWithHint(Command parent, string name, string description, Func<ParseResult, CertificateRequestsApiClient, CancellationToken, Task<int>> run,
            string forbiddenHint, params Symbol[] symbols)
        {
            var sub = new Command(name, description);
            foreach (var symbol in symbols)
            {
                if (symbol is Option option) sub.Options.Add(option);
                else if (symbol is Argument argument) sub.Arguments.Add(argument);
            }
            sub.SetAction(async (result, ct) =>
            {
                var session = await SessionResolver.ResolveAsync(result, tokenOption, apiUrlOption, identityUrlOption, ct);
                if (session is null) return 1;
                return await CliApi.RunAsync(() => run(result, CliApi.CreateClient(session), ct), forbiddenHint);
            });
            parent.Subcommands.Add(sub);
            return sub;
        }

        bool Json(ParseResult r) => r.GetValue(outputOption) == "json";

        var stage = new Command("stage", "The CA default stage and per-template overrides");
        pqc.Subcommands.Add(stage);

        Sub(stage, "show", ShowHelp, async (r, api, ct) =>
        {
            var settings = await api.GetSettingsAsync(ct);
            if (Json(r)) return CliApi.PrintJson(new { pqcStage = settings.PqcStage });
            Console.WriteLine(settings.PqcStage);
            return 0;
        });

        var stageArg = new Argument<string>("stage") { Description = $"New CA default stage, case-insensitive: {string.Join(", ", Enum.GetNames<PqcStage>())}." };
        var setCmd = Sub(stage, "set", SetHelp, async (r, api, ct) =>
        {
            if (ParseStage(r.GetValue(stageArg)!) is not { } value)
            {
                await Console.Error.WriteLineAsync($"error: unknown stage '{r.GetValue(stageArg)}'; use one of {string.Join(", ", Enum.GetNames<PqcStage>())}.");
                return 1;
            }
            var settings = await api.SetPqcStageAsync(value, ct);
            if (Json(r)) return CliApi.PrintJson(new { pqcStage = settings.PqcStage });
            Console.WriteLine($"PQC stage is now {settings.PqcStage}");
            return 0;
        }, stageArg);
        _ = setCmd;

        var templateId = new Argument<Guid>("id") { Description = "Template id (GUID)." };
        var templateStage = new Option<string?>("--stage") { Description = $"Stage for this template, case-insensitive: {string.Join(", ", Enum.GetNames<PqcStage>())}. Give exactly one of --stage or --clear." };
        var clear = new Option<bool>("--clear") { Description = "Remove the override so the template follows the CA default stage. Give exactly one of --stage or --clear." };
        Sub(stage, "template", TemplateHelp, async (r, api, ct) =>
        {
            var stageText = r.GetValue(templateStage);
            if (ValidateTemplateStageArguments(stageText, r.GetValue(clear)) is { } problem)
            {
                await Console.Error.WriteLineAsync($"error: {problem}");
                return 1;
            }
            var template = await api.SetTemplatePqcStageAsync(new CertificateTemplateId(r.GetValue(templateId)),
                r.GetValue(clear) ? null : ParseStage(stageText!), ct);
            if (Json(r)) return CliApi.PrintJson(template);
            Console.WriteLine($"{template.Name}: {template.PqcStageOverride?.ToString() ?? "follows the CA default"}");
            return 0;
        }, templateId, templateStage, clear);

        var exceptions = new Command("exceptions", "Time-limited exceptions that let one identity keep a classical key");
        pqc.Subcommands.Add(exceptions);

        var all = new Option<bool>("--all") { Description = "Also list expired and revoked exceptions. Default: only active ones." };
        Sub(exceptions, "list", ListHelp, async (r, api, ct) =>
        {
            var items = await api.GetPqcExceptionsAsync(r.GetValue(all), ct);
            if (Json(r)) return CliApi.PrintJson(items);
            if (items.Count == 0) { Console.WriteLine("No exceptions."); return 0; }
            Console.WriteLine($"{"State",-8}  {"Template",-16}  {"Family",-6}  {"Name",-32}  {"Expires",-10}  Id");
            foreach (var e in items)
                Console.WriteLine($"{StateOf(e),-8}  {CliApi.Trunc(e.TemplateTypeKey, 16),-16}  {e.Family,-6}  {CliApi.Trunc(e.NamePattern, 32),-32}  {e.ExpiresAtUtc:yyyy-MM-dd}  {e.Id}");
            return 0;
        }, all);

        Sub(exceptions, "create", CreateHelp, async (r, api, ct) =>
        {
            if (BuildCreateRequest(r, TimeProvider.System.GetUtcNow().UtcDateTime) is not { } request)
            {
                await Console.Error.WriteLineAsync($"error: {CreateArgumentError(r)}");
                return 1;
            }
            var created = await api.CreatePqcExceptionAsync(request, ct);
            if (Json(r)) return CliApi.PrintJson(created);
            Console.WriteLine($"granted   {created.Id}");
            Console.WriteLine($"  {created.Family} on {created.TemplateTypeKey} for {created.NamePattern} until {created.ExpiresAtUtc:yyyy-MM-dd}");
            return 0;
        }, TemplateOption, NameOption, FamilyOption, DaysOption, ReasonOption);

        var revokeId = new Argument<Guid>("id") { Description = "Exception id (GUID, as printed by 'qca pqc exceptions list')." };
        Sub(exceptions, "revoke", RevokeHelp, async (r, api, ct) =>
        {
            var revoked = await api.RevokePqcExceptionAsync(new PqcExceptionId(r.GetValue(revokeId)), ct);
            if (Json(r)) return CliApi.PrintJson(revoked);
            Console.WriteLine($"revoked   {revoked.Id}");
            return 0;
        }, revokeId);

        SubWithHint(pqc, "report", ReportHelp, async (r, api, ct) =>
        {
            var (query, error) = BuildReportQuery(r);
            if (query is null)
            {
                await Console.Error.WriteLineAsync($"error: {error}");
                return 1;
            }

            // JSON is the whole report in one document, like `qca cert inventory`; the table is one page.
            if (Json(r)) return CliApi.PrintJson(await CollectAllPagesAsync(api, query, ct));

            foreach (var line in ReportLines(await api.GetPqcMigrationReportAsync(query, ct)))
                Console.WriteLine(line);
            return 0;
        }, "the report needs certificates.view", ReportTemplateOption, ReportStageOption, ReportDaysOption, ReportPageOption, ReportPageSizeOption);

        return pqc;
    }

    private const string ShowHelp =
        "Show the CA's default PQC stage.\n\n" +
        "Prints the stage (Off, Observe, Warn, Pilot or Enforce) that applies to every template without its own override. It reads the CA settings, which need settings.edit; admins pass that check.\n" +
        "Needs: settings.edit or the admin role.\n" +
        "Exit codes: 0 shown; 1 not signed in or the call failed (403 when you lack the permission).\n" +
        "Output: --output json prints {\"pqcStage\":\"<Stage>\"}.\n" +
        "Example: qca pqc stage show";

    private const string SetHelp =
        "Set the CA default PQC stage.\n\n" +
        "Sets how requests with a classical (RSA or ECDSA) key are treated unless a template overrides it: Off allows them silently, Observe records an event, Warn also warns the requester, Pilot refuses new requests but lets renewals through with a warning, Enforce refuses all. Changes the CA setting for new, updated, renewed and approved requests, and for requests already queued; when the stage actually changes it writes an audit entry (PqcStageChanged) and raises a webhook (setting the current stage again does neither). It does not ask for confirmation, including when loosening.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 set; 1 unknown stage, not signed in, or the call failed (403 means you are not admin).\n" +
        "Output: --output json prints {\"pqcStage\":\"<Stage>\"}.\n" +
        "Example: qca pqc stage set Pilot";

    private const string TemplateHelp =
        "Set or clear one template's PQC stage override.\n\n" +
        "With --stage the template uses that stage instead of the CA default; with --clear it follows the CA default again. Give exactly one of the two. Sets the override on the template only; when the override actually changes it writes an audit entry (TemplatePqcStageChanged) and raises a webhook (repeating the current value does neither).\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 set; 1 neither or both of --stage/--clear, unknown stage, not signed in, or the call failed (403 means you are not admin, 404 no such template).\n" +
        "Output: --output json prints the template; otherwise '<name>: <stage or follows the CA default>'.\n" +
        "Example: qca pqc stage template 3f2c9a1e-0000-0000-0000-000000000000 --stage Warn";

    private const string ListHelp =
        "List PQC exceptions.\n\n" +
        "An exception lets one DNS name or suffix on one template keep a classical key for a limited time. Prints state (ACTIVE, EXPIRED or REVOKED), template, family, name, expiry date and id, soonest expiry first. By default only active exceptions are listed.\n" +
        "Needs: the admin role (reads included).\n" +
        "Exit codes: 0 listed (also when there are none); 1 not signed in or the call failed (403 means you are not admin).\n" +
        "Output: --output json prints the array of exceptions as camelCase JSON.\n" +
        "Example: qca pqc exceptions list --all";

    private const string CreateHelp =
        "Grant a time-limited PQC exception for one name on one template.\n\n" +
        "Creates an exception that turns a Pilot or Enforce refusal of a classical key (rsa or ecdsa) into a warning for requests whose every name is covered by --name on --template, until now plus --days. It never applies to CA keys. Exceptions cannot be edited; to change one, revoke it and create another. Writes an audit entry (PqcExceptionCreated) and raises a webhook.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 granted; 1 --family not rsa/ecdsa, --days outside 1 to 3650, not signed in, or the call failed (403 not admin, 404 unknown template, 400 invalid name, reason or a lifetime above the server cap).\n" +
        "Output: --output json prints the created exception; otherwise 'granted <id>' and a summary line.\n" +
        "Example: qca pqc exceptions create --template WebServer --name legacy.example.com --family rsa --days 90 --reason \"Vendor appliance cannot do ML-DSA yet\"";

    private const string RevokeHelp =
        "Revoke a PQC exception so it stops applying.\n\n" +
        "Revokes the exception at once; it is kept in the list (see --all) as REVOKED and cannot be restored: create a new one instead. Requests are re-evaluated against current exceptions at approval and issuance. Writes an audit entry (PqcExceptionRevoked) and raises a webhook.\n" +
        "Needs: the admin role (not a grantable permission).\n" +
        "Exit codes: 0 revoked; 1 not signed in or the call failed (403 not admin, 404 no such exception, 409 already revoked).\n" +
        "Output: --output json prints the revoked exception; otherwise 'revoked <id>'.\n" +
        "Example: qca pqc exceptions revoke 3f2c9a1e-0000-0000-0000-000000000000";

    private const string ReportHelp =
        "Report what a PQC stage would do to live certificates and in-flight requests.\n\n" +
        "Read-only: computes on demand, writes nothing. Per template it counts live Issued certificates and Pending/Approved requests as compliant, allowed, warned, refused or covered by an exception, and lists each classical item with its verdict. --proposed-stage judges everything as if that stage were set; without it each template's own stage is used. The observed block (stage events over --days) needs settings.edit; without it the table prints 'observed: withheld (needs settings.edit)' and the JSON has \"observed\": null with \"withheld\": [\"observed\"]. It makes no readiness or security claim.\n" +
        "Needs: certificates.view (settings.edit for the observed block).\n" +
        "Exit codes: 0 reported; 1 an option out of range or unknown stage, not signed in, or the call failed.\n" +
        "Output: table is one page of items; --output json prints the whole report as one camelCase document with every page of items merged.\n" +
        "Example: qca pqc report --proposed-stage Enforce --template WebServer";

    private static readonly Option<string?> ReportTemplateOption = new("--template") { Description = "Limit the report to one template type key, e.g. WebServer. Default: all templates." };
    private static readonly Option<string?> ReportStageOption = new("--proposed-stage") { Description = $"Judge every template under this stage instead of its own, case-insensitive: {string.Join(", ", Enum.GetNames<PqcStage>())}. Default: each template's current stage." };
    private static readonly Option<int> ReportDaysOption = new("--days") { Description = "Days of observed stage events to count, 1 to 365; the server clamps it to the diagnostic retention (30 days as shipped) and the output states both. Default: 30.", DefaultValueFactory = _ => 30 };
    private static readonly Option<int> ReportPageOption = new("--page") { Description = "Page of items, 1 or more; table output only (--output json collects every page). Default: 1.", DefaultValueFactory = _ => 1 };
    private static readonly Option<int> ReportPageSizeOption = new("--page-size") { Description = "Items per page, 1 to 500; table output only (--output json collects every page). Default: 50.", DefaultValueFactory = _ => 50 };

    /// <summary>The query the parsed options describe, or the reason they are unusable.</summary>
    internal static (PqcReportQuery? Query, string? Error) BuildReportQuery(ParseResult result)
    {
        PqcStage? proposed = null;
        if (result.GetValue(ReportStageOption) is { } text)
        {
            proposed = ParseStage(text);
            if (proposed is null)
                return (null, $"Unknown stage '{text}'; use one of {string.Join(", ", Enum.GetNames<PqcStage>())}.");
        }

        var query = new PqcReportQuery
        {
            TemplateTypeKey = result.GetValue(ReportTemplateOption),
            ProposedStage = proposed,
            ObservedDays = result.GetValue(ReportDaysOption),
            Page = result.GetValue(ReportPageOption),
            PageSize = result.GetValue(ReportPageSizeOption)
        };
        return query.Validate() is { } invalid ? (null, invalid) : (query, null);
    }

    /// <summary>Every page of items merged into one report, 500 at a time.</summary>
    internal static async Task<PqcMigrationReportResponse> CollectAllPagesAsync(
        CertificateRequestsApiClient api, PqcReportQuery query, CancellationToken cancellationToken)
    {
        PqcMigrationReportResponse? first = null;
        var items = new List<PqcReportItem>();
        for (var page = 1; ; page++)
        {
            var report = await api.GetPqcMigrationReportAsync(query.WithPage(page, 500), cancellationToken);
            first ??= report;
            items.AddRange(report.Items.Items);
            if (report.Items.Items.Count == 0 || page >= report.Items.TotalPages) break;
        }
        return first!.WithItems(new PagedResult<PqcReportItem>
        {
            Items = items, TotalCount = first.Items.TotalCount, Page = 1, PageSize = Math.Max(items.Count, 1)
        });
    }

    /// <summary>The table form: per-template summary, one page of items, the observed block or its absence, then the scope note.</summary>
    internal static IReadOnlyList<string> ReportLines(PqcMigrationReportResponse report)
    {
        var lines = new List<string>
        {
            report.ProposedStage is { } proposed
                ? $"Judged under {proposed} (CA default today: {report.CaDefaultStage})"
                : $"Judged under each template's own stage (CA default: {report.CaDefaultStage})",
            "",
            $"{"Template",-22} {"Stage",-17} {"Live",4} {"Compl",5} {"Allow",5} {"Warn",4} {"Refuse",6} {"Exc",3} {"Assum",5} {"InFl",4} {"N/A",4}"
        };
        foreach (var t in report.Templates)
            lines.Add($"{CliApi.Trunc(t.Name, 22),-22} {t.CurrentStage + " -> " + t.ProposedStage,-17} {t.LiveTotal,4} {t.Compliant,5} "
                      + $"{t.ClassicalAllowed,5} {t.ClassicalWarned,4} {t.ClassicalRefused,6} {t.ClassicalCoveredByException,3} "
                      + $"{t.AlgorithmAssumed,5} {t.InFlight,4} {t.NotAffected,4}");

        lines.Add("");
        if (report.Items.TotalCount == 0)
        {
            lines.Add("No classical certificates or requests in scope.");
        }
        else
        {
            lines.Add($"{"Common name",-32} {"Template",-14} {"Key",-10} {"Verdict",-19} {"Expires",-10} {"Kind",-9} Note");
            foreach (var i in report.Items.Items)
                lines.Add($"{CliApi.Trunc(i.CommonName, 32),-32} {CliApi.Trunc(i.TemplateTypeKey, 14),-14} {i.KeyAlgorithm,-10} "
                          + $"{i.Verdict,-19} {i.ValidToUtc?.ToString("yyyy-MM-dd") ?? "-",-10} {(i.InFlight ? "in flight" : "live"),-9} "
                          + $"{(i.AlgorithmAssumed ? "assumed key algorithm" : "")}");
            lines.Add($"Page {report.Items.Page} of {Math.Max(report.Items.TotalPages, 1)}, {report.Items.TotalCount} items");
        }

        lines.Add("");
        if (report.Observed is { } observed)
        {
            lines.Add($"Observed over {observed.EffectiveDays} of the {observed.RequestedDays} days asked "
                      + $"(events are kept {observed.RetentionDays} days): {observed.TotalEvents} events, {observed.DistinctIdentities} identities");
            foreach (var c in observed.Counts)
                lines.Add($"  {c.TemplateTypeKey,-16} {c.Source,-9} {c.Kind,-16} {c.Count,5}  ({c.DistinctIdentities} identities)");
        }
        else
        {
            lines.Add("observed: withheld (needs settings.edit)");
        }

        lines.Add("");
        lines.Add(PqcMigrationReportNotes.Scope);
        return lines;
    }

    /// <summary>The stage named by <paramref name="text"/>, case-insensitively; null when it names none (numbers included).</summary>
    internal static PqcStage? ParseStage(string text) =>
        !string.IsNullOrWhiteSpace(text) && !char.IsDigit(text.Trim()[0])
        && Enum.TryParse<PqcStage>(text.Trim(), ignoreCase: true, out var stage) && Enum.IsDefined(stage)
            ? stage
            : null;

    /// <summary>The classical family named by <paramref name="text"/> (rsa or ecdsa); null otherwise.</summary>
    internal static PqcExceptionFamily? ParseFamily(string text) =>
        text.Trim().ToLowerInvariant() switch
        {
            "rsa" => PqcExceptionFamily.Rsa,
            "ecdsa" => PqcExceptionFamily.Ecdsa,
            _ => null
        };

    /// <summary>Exactly one of --stage or --clear, and a real stage; null when the arguments are usable.</summary>
    internal static string? ValidateTemplateStageArguments(string? stage, bool clear) =>
        (stage is not null, clear) switch
        {
            (false, false) => "Pass --stage, or --clear.",
            (true, true) => "Pass either --stage or --clear, not both.",
            (true, false) when ParseStage(stage!) is null =>
                $"Unknown stage '{stage}'; use one of {string.Join(", ", Enum.GetNames<PqcStage>())}.",
            _ => null
        };

    /// <summary>Null when <paramref name="days"/> is 1 to 3650; the server may cap it lower.</summary>
    internal static string? ValidateDays(int days) =>
        days is >= 1 and <= 3650 ? null : "--days must be between 1 and 3650.";

    /// <summary>The create request the parsed options describe, or null when an option is unusable (see <see cref="CreateArgumentError"/>).</summary>
    internal static CreatePqcExceptionRequest? BuildCreateRequest(ParseResult result, DateTime nowUtc)
    {
        if (CreateArgumentError(result) is not null) return null;
        return new CreatePqcExceptionRequest
        {
            TemplateTypeKey = result.GetValue(TemplateOption)!,
            NamePattern = result.GetValue(NameOption)!,
            Family = ParseFamily(result.GetValue(FamilyOption)!)!.Value,
            ExpiresAtUtc = nowUtc.AddDays(result.GetValue(DaysOption)),
            Reason = result.GetValue(ReasonOption)!
        };
    }

    private static string? CreateArgumentError(ParseResult result) =>
        ParseFamily(result.GetValue(FamilyOption) ?? "") is null
            ? "--family must be rsa or ecdsa; post-quantum keys need no exception."
            : ValidateDays(result.GetValue(DaysOption));

    private static string StateOf(PqcExceptionResponse e) =>
        e.RevokedAtUtc is not null ? "REVOKED" : e.IsActive ? "ACTIVE" : "EXPIRED";
}
