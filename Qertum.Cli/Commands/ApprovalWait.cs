using Qertum.Services;

namespace Qertum.Cli.Commands;

/// <summary>
/// What <c>qca requests approve --wait</c> does after the approval: poll until the request is issued (or ends
/// badly) and turn the outcome into an exit code a script can act on: 0 issued, 1 rejected or a failed call,
/// 3 timed out while still on its way. The result goes to stdout, progress to stderr.
/// </summary>
internal static class ApprovalWait
{
    internal const int MinTimeoutSeconds = 1;
    internal const int MaxTimeoutSeconds = 3600;

    /// <summary>Null when <paramref name="seconds"/> is usable; otherwise why not. Checked before anything is approved.</summary>
    internal static string? ValidateTimeout(int seconds) =>
        seconds is < MinTimeoutSeconds or > MaxTimeoutSeconds
            ? $"--timeout must be between {MinTimeoutSeconds} and {MaxTimeoutSeconds} seconds."
            : null;

    /// <summary>The worst of two exit codes: a failure (1) beats a timeout (3) beats success (0).</summary>
    internal static int Merge(int current, int next) =>
        current == 1 || next == 1 ? 1
        : current == 3 || next == 3 ? 3
        : 0;

    internal static async Task<int> RunAsync(
        CertificateRequestsApiClient client, CertificateRequest approved, TimeSpan timeout,
        TextWriter stdout, TextWriter stderr, CancellationToken ct)
    {
        var id = (Guid)approved.Id;
        if (approved.Status.IsFinal())
            return await ReportAsync(new WaitResult(WaitOutcome.Final, approved), id, timeout, stdout, stderr);

        await stderr.WriteLineAsync($"waiting for issuance of {id} (status {approved.Status}) …");
        var lastStatus = approved.Status;
        var result = await client.WaitForFinalAsync(approved.Id, timeout, async update =>
        {
            if (update.Status != lastStatus)
            {
                lastStatus = update.Status;
                await stderr.WriteLineAsync($"  status {update.Status}");
            }
        }, ct);

        return await ReportAsync(result, id, timeout, stdout, stderr);
    }

    private static async Task<int> ReportAsync(WaitResult result, Guid id, TimeSpan timeout, TextWriter stdout, TextWriter stderr)
    {
        switch (result.Outcome)
        {
            case WaitOutcome.NotFound:
                await stderr.WriteLineAsync($"failed    {id}  — not found while waiting for issuance");
                return 1;
            case WaitOutcome.TimedOut:
                await stderr.WriteLineAsync(
                    $"timeout   {id}  — still {result.Request?.Status} after {timeout.TotalSeconds:0.#} s; the queue consumer may be busy or down");
                return 3;
        }

        var request = result.Request!;
        switch (request.Status)
        {
            case CertificateRequestStatus.Issued:
                await stdout.WriteLineAsync($"issued    {id}");
                return 0;
            case CertificateRequestStatus.Rejected:
                await stderr.WriteLineAsync($"failed    {id}  — rejected: {(string.IsNullOrWhiteSpace(request.FailureReason) ? "no reason recorded" : request.FailureReason)}");
                return 1;
            default:
                await stderr.WriteLineAsync($"failed    {id}  — ended as {request.Status}, not issued");
                return 1;
        }
    }
}
