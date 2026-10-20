using Serilog;

namespace Qertum.Services.Lifecycle;

/// <summary>How long the audit files are kept, so the table never keeps what the files dropped.</summary>
public static class AuditRetention
{
    /// <summary>
    /// <c>RetainedFileCountLimit</c> files of <c>RollingInterval</c> each, or null for
    /// <c>Infinite</c> (files are never rolled away). Months and years are rounded up (31 and 366
    /// days) so the table errs towards keeping a row the file still holds.
    /// </summary>
    public static TimeSpan? WindowFor(AuditLogOptions options)
    {
        var interval = Enum.TryParse<RollingInterval>(options.File.RollingInterval, ignoreCase: true, out var parsed)
            ? parsed
            : RollingInterval.Day;
        var files = Math.Max(1, options.File.RetainedFileCountLimit);

        return interval switch
        {
            RollingInterval.Infinite => null,
            RollingInterval.Year => TimeSpan.FromDays(366 * files),
            RollingInterval.Month => TimeSpan.FromDays(31 * files),
            RollingInterval.Day => TimeSpan.FromDays(files),
            RollingInterval.Hour => TimeSpan.FromHours(files),
            RollingInterval.Minute => TimeSpan.FromMinutes(files),
            _ => TimeSpan.FromDays(files),
        };
    }
}
