using System.CommandLine;
using System.Globalization;
using System.Text.Json;
using Qertum.Cli.Api;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary>Which certificates a <c>qca bulk</c> call selects, as typed on the command line.</summary>
/// <param name="Issuer">Only certificates under this issuer.</param>
/// <param name="Template">Only this template key.</param>
/// <param name="Owner">Only this owner subject.</param>
/// <param name="ExpiresWithin">Only certificates expiring within this many days (already expired ones included).</param>
/// <param name="Cn">Only common names containing this text.</param>
/// <param name="All">Every eligible certificate; cannot be combined with another field.</param>
internal sealed record BulkSelection(Guid? Issuer, string? Template, string? Owner, int? ExpiresWithin, string? Cn, bool All);

/// <summary>
/// <c>qca bulk</c>: revoke or renew many certificates in one operation. A bulk call previews first (the server
/// freezes the affected set and counts it), then executes on a separate call that must repeat the count.
/// </summary>
internal static class BulkCommands
{
    private static readonly JsonSerializerOptions JsonPrint = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private static readonly Option<Guid?> IssuerOption = new("--issuer") { Description = "Only certificates signed under this issuer (a GUID, see 'qca issuers list'). Default: no issuer filter." };
    private static readonly Option<string?> TemplateOption = new("--template") { Description = "Only certificates of this template type key, e.g. WebServer. Default: no template filter." };
    private static readonly Option<string?> OwnerOption = new("--owner") { Description = "Only certificates owned by this subject (the stable identity subject, not the display name). Default: no owner filter." };
    private static readonly Option<int?> ExpiresWithinOption = new("--expires-within") { Description = "Only certificates that expire within this many days, 0 to 36500; already-expired issued certificates are included. Default: no expiry filter." };
    private static readonly Option<string?> CnOption = new("--cn") { Description = "Only common names containing this text, matched literally. Default: no name filter." };
    private static readonly Option<bool> AllOption = new("--all") { Description = "Select every eligible certificate. Cannot be combined with another filter option. Default: off; without it at least one filter option is required." };
    private static readonly Option<string?> ReasonOption = new("--reason") { Description = "Why the certificates are revoked (revoke only, required, at most 500 characters; kept in the audit entries)." };
    private static readonly Option<bool> YesOption = new("--yes") { Description = "Preview and execute in one call. Needs --confirm-count. Default: off (preview only, then run 'qca bulk execute')." };
    private static readonly Option<int?> ConfirmCountOption = new("--confirm-count") { Description = "The number of certificates you expect the operation to affect. With --yes, nothing runs if the preview finds a different number." };
    private static readonly Option<bool> WaitOption = new("--wait") { Description = "After executing, wait until the operation finishes, polling as the server's Retry-After hint says. Progress goes to stderr. Default: off (return once the operation is accepted)." };
    private static readonly Option<int> TimeoutOption = new("--timeout") { Description = "With --wait: seconds to wait, 1 to 3600. Default 60.", DefaultValueFactory = _ => 60 };

    private const string RevokeHelp =
        "Revoke many certificates: preview the affected set, optionally run it.\n" +
        "\n" +
        "Creates a bulk operation that freezes the matching issued certificates and changes nothing else. Pass --yes with --confirm-count to run it straight away; otherwise it stops after the preview and prints the 'qca bulk execute' command. Running revokes each certificate through the normal revocation path, so every one is audited and queued for the CRL. Choose the certificates with --issuer, --template, --owner, --expires-within, --cn, or --all.\n" +
        "Needs: certificates.manage.\n" +
        "Exit codes: 0 previewed (or, with --yes --wait, completed); 1 not signed in, bad options, a refused call, a count mismatch, or an operation that completed with errors; 3 --wait timed out while the operation was still running.\n" +
        "Output: the operation id, item count and exclusions, then the command to run it; --output json prints the preview object.\n" +
        "Example: qca bulk revoke --issuer 3f2c9a1e-0000-0000-0000-000000000000 --reason \"issuer key compromised\"";

    private const string RenewHelp =
        "Renew many certificates: preview the affected set, optionally run it.\n" +
        "\n" +
        "Creates a bulk operation that freezes the matching issued certificates and changes nothing else. Running files a renewal request per certificate, which starts Pending and still needs approval; originals are left untouched. CA certificates, ACME and EST certificates whose key the client holds, and certificates that already have a renewal are left out and reported. Pass --yes with --confirm-count to run it straight away.\n" +
        "Needs: certificates.create.\n" +
        "Exit codes: 0 previewed (or, with --yes --wait, completed); 1 not signed in, bad options, a refused call, a count mismatch, or an operation that completed with errors; 3 --wait timed out while the operation was still running.\n" +
        "Output: the operation id, item count and exclusions, then the command to run it; --output json prints the preview object.\n" +
        "Example: qca bulk renew --expires-within 30";

    private const string ExecuteHelp =
        "Run a previewed bulk operation.\n" +
        "\n" +
        "Changes the certificates frozen by the preview: revokes them, or files renewal requests, depending on the operation. --confirm-count must equal the previewed count. A preview expires after the server's BulkOperations:PreviewTtlMinutes (default 60) and a started operation cannot be started again.\n" +
        "Needs: certificates.manage for a revoke operation, certificates.create for a renew operation; being the operation's creator or an admin.\n" +
        "Exit codes: 0 accepted (or, with --wait, completed); 1 not signed in, a refused call, or an operation that completed with errors, was cancelled or expired; 3 --wait timed out while the operation was still running.\n" +
        "Output: the operation's state; with --wait one progress line per change on stderr and a final line on stdout.\n" +
        "Example: qca bulk execute 3f2c9a1e-0000-0000-0000-000000000000 --confirm-count 120 --wait";

    private const string ShowHelp =
        "Show one bulk operation, with its failed items.\n" +
        "\n" +
        "Reads the operation and lists up to 20 items that failed or were skipped, with the reason.\n" +
        "Needs: certificates.manage for a revoke operation, certificates.create for a renew operation; being the operation's creator or an admin.\n" +
        "Exit codes: 0 shown; 1 not signed in, or no such operation.\n" +
        "Output: key/value lines, then the failed items; --output json prints the operation object.\n" +
        "Example: qca bulk show 3f2c9a1e-0000-0000-0000-000000000000";

    private const string ListHelp =
        "List bulk operations.\n" +
        "\n" +
        "Lists your bulk operations, newest first; an admin sees everyone's.\n" +
        "Needs: a signed-in session.\n" +
        "Exit codes: 0 listed; 1 not signed in.\n" +
        "Output: one line per operation (id, kind, status, items, done/skipped/failed); --output json prints the page.\n" +
        "Example: qca bulk list --page 1";

    private const string CancelHelp =
        "Cancel a bulk operation that has only been previewed.\n" +
        "\n" +
        "Changes the operation to Cancelled so it can no longer be executed; no certificate is touched. An operation that already started cannot be cancelled.\n" +
        "Needs: certificates.manage for a revoke operation, certificates.create for a renew operation; being the operation's creator or an admin.\n" +
        "Exit codes: 0 cancelled; 1 not signed in, no such operation, or it is no longer previewed.\n" +
        "Output: the operation's state; --output json prints the operation object.\n" +
        "Example: qca bulk cancel 3f2c9a1e-0000-0000-0000-000000000000";

    public static Command Build(
        Option<string?> apiUrlOption,
        Option<string?> identityUrlOption,
        Option<string?> tokenOption,
        Option<string> outputOption)
    {
        var bulk = new Command("bulk", "Bulk revoke and renew of certificates");

        Command Sub(string name, string description, Func<ParseResult, CertificateRequestsApiClient, CancellationToken, Task<int>> run,
            params Symbol[] symbols)
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
                return await CliApi.RunAsync(() => run(result, CliApi.CreateClient(session), ct));
            });
            bulk.Subcommands.Add(sub);
            return sub;
        }

        bool Json(ParseResult r) => r.GetValue(outputOption) == "json";
        BulkSelection Selection(ParseResult r) => new(r.GetValue(IssuerOption), r.GetValue(TemplateOption), r.GetValue(OwnerOption),
            r.GetValue(ExpiresWithinOption), r.GetValue(CnOption), r.GetValue(AllOption));

        Option[] filterOptions = [IssuerOption, TemplateOption, OwnerOption, ExpiresWithinOption, CnOption, AllOption];

        Sub("revoke", RevokeHelp,
            (r, api, ct) => RunPreviewAsync(api, BulkOperationKind.Revoke, Selection(r), r.GetValue(ReasonOption), r.GetValue(YesOption),
                r.GetValue(ConfirmCountOption), r.GetValue(WaitOption), r.GetValue(TimeoutOption), Json(r), Console.Out, Console.Error, ct),
            [.. filterOptions, ReasonOption, YesOption, ConfirmCountOption, WaitOption, TimeoutOption]);

        Sub("renew", RenewHelp,
            (r, api, ct) => RunPreviewAsync(api, BulkOperationKind.Renew, Selection(r), null, r.GetValue(YesOption),
                r.GetValue(ConfirmCountOption), r.GetValue(WaitOption), r.GetValue(TimeoutOption), Json(r), Console.Out, Console.Error, ct),
            [.. filterOptions, YesOption, ConfirmCountOption, WaitOption, TimeoutOption]);

        var idArg = new Argument<Guid>("id") { Description = "The bulk operation id (a GUID, printed by the preview). Required." };
        var confirmRequired = new Option<int>("--confirm-count") { Description = "The number of certificates the operation was previewed with (required). Must match exactly.", Required = true };

        Sub("execute", ExecuteHelp,
            (r, api, ct) => RunExecuteAsync(api, new BulkOperationId(r.GetValue(idArg)), r.GetValue(confirmRequired), r.GetValue(WaitOption),
                r.GetValue(TimeoutOption), Json(r), Console.Out, Console.Error, ct),
            idArg, confirmRequired, WaitOption, TimeoutOption);

        Sub("show", ShowHelp, async (r, api, ct) =>
        {
            var operation = await api.GetBulkOperationAsync(new BulkOperationId(r.GetValue(idArg)), ct);
            if (operation is null)
            {
                await Console.Error.WriteLineAsync("error: no such bulk operation");
                return 1;
            }
            var problems = operation.FailedCount + operation.SkippedCount > 0
                ? (await api.GetBulkOperationItemsAsync(operation.Id, null, 1, 200, ct)).Items
                    .Where(i => i.Outcome is BulkItemOutcome.Failed or BulkItemOutcome.Skipped).Take(20).ToList()
                : [];
            if (Json(r)) return CliApi.PrintJson(new { operation, problemItems = problems });
            WriteOperation(operation, Console.Out);
            foreach (var item in problems)
                Console.WriteLine($"  {item.Outcome.ToString().ToLowerInvariant(),-8} {item.RequestId}  {item.CommonName}  {item.Detail}");
            return 0;
        }, idArg);

        var pageOption = new Option<int>("--page") { Description = "Page number, 1 or more. Default 1.", DefaultValueFactory = _ => 1 };
        Sub("list", ListHelp, async (r, api, ct) =>
        {
            var page = await api.ListBulkOperationsAsync(Math.Max(r.GetValue(pageOption), 1), 50, ct);
            if (Json(r)) return CliApi.PrintJson(page);
            foreach (var o in page.Items)
                Console.WriteLine(string.Create(CultureInfo.InvariantCulture,
                    $"{o.Id}  {o.Kind,-6}  {o.Status,-19}  {o.ItemCount,6} items  {o.DoneCount}/{o.SkippedCount}/{o.FailedCount}  {o.CreatedAtUtc:u}  {o.CreatedBy}"));
            if (page.TotalPages > page.Page) Console.WriteLine($"page {page.Page} of {page.TotalPages}");
            return 0;
        }, pageOption);

        Sub("cancel", CancelHelp, async (r, api, ct) =>
        {
            var operation = await api.CancelBulkOperationAsync(new BulkOperationId(r.GetValue(idArg)), ct);
            if (Json(r)) return CliApi.PrintJson(operation);
            WriteOperation(operation, Console.Out);
            return 0;
        }, idArg);

        return bulk;
    }

    /// <summary>Null when the selection is usable; otherwise why not. Checked before any call.</summary>
    internal static string? ValidateSelection(BulkSelection s)
    {
        var criteria = s.Issuer is not null || !string.IsNullOrWhiteSpace(s.Template) || !string.IsNullOrWhiteSpace(s.Owner)
            || s.ExpiresWithin is not null || !string.IsNullOrWhiteSpace(s.Cn);
        if (s.All && criteria) return "--all cannot be combined with another filter option.";
        if (!s.All && !criteria) return "choose at least one of --issuer, --template, --owner, --expires-within, --cn, or pass --all.";
        if (s.ExpiresWithin is < 0 or > 36500) return "--expires-within must be between 0 and 36500 days.";
        return null;
    }

    internal static BulkOperationFilter ToFilter(BulkSelection s) => new()
    {
        IssuerId = s.Issuer is { } issuer ? new IssuerId(issuer) : null,
        TemplateKey = s.Template,
        OwnerSubject = s.Owner,
        ExpiresWithinDays = s.ExpiresWithin,
        CommonNameContains = s.Cn,
        All = s.All
    };

    /// <summary>
    /// Preview, and with <paramref name="yes"/> execute. Every check that can fail without a server runs first, so a bad
    /// call changes nothing. With <paramref name="yes"/> the preview's count must equal <paramref name="confirmCount"/> or
    /// the operation is left previewed and nothing runs.
    /// </summary>
    internal static async Task<int> RunPreviewAsync(
        CertificateRequestsApiClient client, BulkOperationKind kind, BulkSelection selection, string? reason,
        bool yes, int? confirmCount, bool wait, int timeoutSeconds, bool json, TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        if (ValidateSelection(selection) is { } invalid) return await FailAsync(stderr, invalid);
        if (kind == BulkOperationKind.Revoke && string.IsNullOrWhiteSpace(reason)) return await FailAsync(stderr, "--reason is required to revoke.");
        if (yes && confirmCount is null) return await FailAsync(stderr, "--yes needs --confirm-count.");
        if (ApprovalWait.ValidateTimeout(timeoutSeconds) is { } badTimeout) return await FailAsync(stderr, badTimeout);

        var preview = await client.PreviewBulkOperationAsync(new PreviewBulkOperationRequest(kind, ToFilter(selection), reason), ct);
        var operation = preview.Operation;

        if (!yes)
        {
            if (json) { await stdout.WriteLineAsync(JsonSerializer.Serialize(preview, JsonPrint)); return 0; }
            await WriteOperationAsync(operation, stdout);
            await stdout.WriteLineAsync($"to run: qca bulk execute {operation.Id} --confirm-count {operation.ItemCount}");
            return 0;
        }

        if (operation.ItemCount != confirmCount)
        {
            await stderr.WriteLineAsync(string.Create(CultureInfo.InvariantCulture,
                $"error: the filter now matches {operation.ItemCount}, not {confirmCount}; nothing was run (operation {operation.Id} stays previewed)"));
            return 1;
        }

        return await RunExecuteAsync(client, operation.Id, operation.ItemCount, wait, timeoutSeconds, json, stdout, stderr, ct);
    }

    /// <summary>Executes a previewed operation and, with <paramref name="wait"/>, follows it to the end.</summary>
    internal static async Task<int> RunExecuteAsync(
        CertificateRequestsApiClient client, BulkOperationId id, int confirmCount, bool wait, int timeoutSeconds, bool json,
        TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        if (ApprovalWait.ValidateTimeout(timeoutSeconds) is { } badTimeout) return await FailAsync(stderr, badTimeout);

        var started = await client.ExecuteBulkOperationAsync(id, confirmCount, ct);
        if (!wait)
        {
            if (json) { await stdout.WriteLineAsync(JsonSerializer.Serialize(started, JsonPrint)); return 0; }
            await WriteOperationAsync(started, stdout);
            return 0;
        }

        await stderr.WriteLineAsync($"waiting for bulk operation {id} ({started.ItemCount} items) …");
        var lastDone = -1;
        var result = await client.WaitForBulkOperationAsync(id, TimeSpan.FromSeconds(timeoutSeconds), async update =>
        {
            var processed = update.DoneCount + update.SkippedCount + update.FailedCount;
            if (processed != lastDone)
            {
                lastDone = processed;
                await stderr.WriteLineAsync($"  {processed}/{update.ItemCount} (done {update.DoneCount}, skipped {update.SkippedCount}, failed {update.FailedCount})");
            }
        }, ct);

        switch (result.Outcome)
        {
            case BulkWaitOutcome.NotFound:
                await stderr.WriteLineAsync($"failed    {id}  — not found while waiting");
                return 1;
            case BulkWaitOutcome.TimedOut:
                await stderr.WriteLineAsync(string.Create(CultureInfo.InvariantCulture,
                    $"timeout   {id}  — still {result.Operation?.Status} after {timeoutSeconds} s; the queue consumer may be busy or down"));
                return 3;
        }

        var final = result.Operation!;
        if (json) await stdout.WriteLineAsync(JsonSerializer.Serialize(final, JsonPrint));
        else
        {
            await stdout.WriteLineAsync(final.Status switch
            {
                BulkOperationStatus.Completed => $"completed {id}: {final.DoneCount} done, {final.SkippedCount} skipped",
                BulkOperationStatus.CompletedWithErrors => $"completed with errors {id}: {final.DoneCount} done, {final.SkippedCount} skipped, {final.FailedCount} failed",
                _ => $"{final.Status.ToString().ToLowerInvariant()} {id}"
            });
            if (final.FailedCount > 0) await stdout.WriteLineAsync($"see the failures: qca bulk show {id}");
        }
        return final.Status == BulkOperationStatus.Completed ? 0 : 1;
    }

    private static async Task<int> FailAsync(TextWriter stderr, string message)
    {
        await stderr.WriteLineAsync($"error: {message}");
        return 1;
    }

    private static void WriteOperation(BulkOperationView o, TextWriter w) => WriteOperationAsync(o, w).GetAwaiter().GetResult();

    private static async Task WriteOperationAsync(BulkOperationView o, TextWriter w)
    {
        await w.WriteLineAsync($"operation {o.Id}");
        await w.WriteLineAsync($"kind {o.Kind}");
        await w.WriteLineAsync($"status {o.Status}");
        await w.WriteLineAsync($"items {o.ItemCount}");
        if (o.Status is not (BulkOperationStatus.Previewed or BulkOperationStatus.Cancelled or BulkOperationStatus.Expired))
            await w.WriteLineAsync($"progress done {o.DoneCount}, skipped {o.SkippedCount}, failed {o.FailedCount}");
        if (!string.IsNullOrWhiteSpace(o.Reason)) await w.WriteLineAsync($"reason {o.Reason}");
        foreach (var (reason, count) in o.Excluded.OrderBy(e => e.Key, StringComparer.Ordinal))
            await w.WriteLineAsync($"excluded {reason} {count}");
        await w.WriteLineAsync($"created by {o.CreatedBy}");
        if (o.ExecutedBy is not null) await w.WriteLineAsync($"executed by {o.ExecutedBy}");
    }
}
