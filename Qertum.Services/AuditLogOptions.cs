namespace Qertum.Services;

/// <summary>
/// Configuration for the Serilog-based audit log. Bind from the "AuditLog" configuration section.
/// </summary>
public sealed class AuditLogOptions
{
    /// <summary>Configuration section key.</summary>
    public const string SectionName = "AuditLog";

    /// <summary>Rolling file sink. Enabled by default; path defaults to {db-dir}/audit-logs/audit-.clef.</summary>
    public FileLogOptions File { get; set; } = new();

    /// <summary>Rolling file sink options.</summary>
    public sealed class FileLogOptions
    {
        /// <summary>Whether to write audit events to a file. Default: true.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Full path to the rolling log file, e.g. <c>/var/log/qertum/audit-.clef</c>.
        /// The date is inserted before the extension by Serilog.
        /// Leave empty to use the default path beside the database.
        /// </summary>
        public string Path { get; set; } = "";

        /// <summary>How often to roll to a new file. Default: Day.</summary>
        public string RollingInterval { get; set; } = "Day";

        /// <summary>How many rolled files to keep. Default: 365 (roughly one year).</summary>
        public int RetainedFileCountLimit { get; set; } = 365;
    }

    /// <summary>Periodic checkpoint of every audit chain head, sent as a webhook event.</summary>
    public CheckpointOptions Checkpoint { get; set; } = new();

    /// <summary>Checkpoint job options.</summary>
    public sealed class CheckpointOptions
    {
        /// <summary>Whether the QueueConsumer sends <c>AuditCheckpoint</c> webhook events. Default: true.</summary>
        public bool Enabled { get; set; } = true;

        /// <summary>Minutes between checkpoints, 1 to 1440. Default: 60. This is the window in which a cut tail goes undetected.</summary>
        public int IntervalMinutes { get; set; } = 60;

        /// <summary>
        /// Directory holding the IdentityService audit log. Empty means <c>{data}/identity/audit-logs</c> when that
        /// directory exists.
        /// </summary>
        public string IdentityDirectory { get; set; } = "";
    }
}
