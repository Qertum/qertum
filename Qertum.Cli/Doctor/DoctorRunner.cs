namespace Qertum.Cli.Doctor;

/// <summary>Runs the checks in order. An unexpected exception in one is that check's failure, not the run's.</summary>
internal static class DoctorRunner
{
    public static async Task<DoctorReport> RunAsync(IEnumerable<IDoctorCheck> checks, DoctorContext context, CancellationToken ct)
    {
        var results = new List<DoctorResult>();
        foreach (var check in checks)
        {
            try
            {
                results.Add(await check.RunAsync(context, ct));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                // The exception type only: its message may carry a URL or response text.
                results.Add(DoctorResult.Of(check.Id, DoctorStatus.Fail, $"the check failed unexpectedly ({ex.GetType().Name})",
                    notVerified: ["everything this check covers"]));
            }
        }

        return new DoctorReport(results);
    }
}
