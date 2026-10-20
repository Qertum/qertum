using System.Net.Http.Headers;
using System.Text.Json;
using Qertum.Cli.Auth;
using Qertum.Services;

namespace Qertum.Cli.Api;

/// <summary>
/// The CLI's one route to the API: the shared <see cref="CertificateRequestsApiClient"/>, whose
/// relative paths keep a path prefix in <c>--api-url</c>, and one way to report a failed call.
/// </summary>
internal static class CliApi
{
    private static readonly JsonSerializerOptions JsonPrint = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static CertificateRequestsApiClient CreateClient(ResolvedSession session)
    {
        var http = new HttpClient { BaseAddress = new Uri(session.ApiUrl.TrimEnd('/') + "/") };
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", session.Token);
        return new CertificateRequestsApiClient(http);
    }

    /// <summary>
    /// Runs one command body. A failed call prints the server's reason (the problem's detail, or its
    /// title) and exits 1, the same way for every command.
    /// </summary>
    /// <param name="forbiddenHint">Appended to a 403, naming what the command needs.</param>
    public static async Task<int> RunAsync(Func<Task<int>> body, string? forbiddenHint = null)
    {
        try
        {
            return await body();
        }
        catch (ApiProblemException ex)
        {
            foreach (var line in FormatProblem(ex, forbiddenHint))
                await Console.Error.WriteLineAsync(line);
            return 1;
        }
        catch (HttpRequestException ex)
        {
            await Console.Error.WriteLineAsync($"error: could not reach the API — {ex.Message}");
            return 1;
        }
    }

    /// <summary>
    /// The stderr lines for a failed call: the status and reason, a policy decision's rule list, then the
    /// server's correlation id when it sent one (for any status: a 403 someone reports needs it too).
    /// </summary>
    internal static IReadOnlyList<string> FormatProblem(ApiProblemException ex, string? forbiddenHint)
    {
        var hint = ex.StatusCode == System.Net.HttpStatusCode.Forbidden && forbiddenHint is not null
            ? $" ({forbiddenHint})"
            : "";
        var lines = new List<string> { $"error: {(int)ex.StatusCode} — {ex.Message}{hint}" };
        if (ex.StepUp is { } stepUp)
        {
            lines.Add("  this operation needs a recent second-factor sign-in");
            lines.Add("  run: qca auth login"
                      + (stepUp.AcrValues is { } acr ? $" --acr-values {acr}" : string.Empty)
                      + (stepUp.MaxAgeSeconds is { } age ? $" --max-age {age}" : string.Empty)
                      + "  (if your identity provider honours them in the device flow; if the token does not change, sign in with a second factor through the provider itself)");
        }
        if (ex.Approval is { } approval)
        {
            lines.Add("  this operation needs a second administrator's approval first");
            lines.Add($"  run: qca approvals request {approval.Operation}"
                      + (approval.TargetId is { } target ? $" --target {target}" : string.Empty)
                      + " --note \"<why>\"");
            lines.Add("  then repeat the operation within the approval's time window (see: qca approvals list --mine)");
        }
        // A policy decision lists every rule that refused the request; that list is the reason.
        lines.AddRange(ex.Violations.Select(v => $"  - {v.Message}"));
        if (!string.IsNullOrEmpty(ex.CorrelationId))
            lines.Add($"  correlation id: {ex.CorrelationId}");
        return lines;
    }

    /// <summary>Prints <paramref name="value"/> as indented camelCase JSON, the <c>--output json</c> form.</summary>
    public static int PrintJson<T>(T value) => PrintJson(value, Console.Out);

    /// <summary>Prints <paramref name="value"/> as indented camelCase JSON to <paramref name="output"/>.</summary>
    public static int PrintJson<T>(T value, TextWriter output)
    {
        output.WriteLine(JsonSerializer.Serialize(value, JsonPrint));
        return 0;
    }

    /// <summary>The stderr lines for a response's stage warnings: <c>warning: …</c>, one each.</summary>
    public static IReadOnlyList<string> FormatWarnings(IReadOnlyList<string>? warnings) =>
        (warnings ?? []).Select(w => $"warning: {w}").ToList();

    /// <summary>Writes stage warnings to stderr, so they never disturb stdout or <c>--output json</c>.</summary>
    public static async Task PrintWarningsAsync(IReadOnlyList<string>? warnings)
    {
        foreach (var line in FormatWarnings(warnings))
            await Console.Error.WriteLineAsync(line);
    }

    public static string Trunc(string? s, int max) =>
        string.IsNullOrEmpty(s) ? "-" : s.Length <= max ? s : s[..(max - 1)] + "…";
}
