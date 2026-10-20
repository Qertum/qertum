namespace Qertum.Services.Lifecycle;

/// <summary>The <c>LifecycleEvents</c> configuration section.</summary>
public sealed class LifecycleEventsOptions
{
    public const string SectionName = "LifecycleEvents";

    /// <summary>Days a diagnostic row is kept. Audit rows follow the audit file retention instead.</summary>
    public int DiagnosticRetentionDays { get; set; } = 30;

    /// <summary>How long the table sink buffers events before writing a batch.</summary>
    public int BufferingTimeLimitMs { get; set; } = 500;
}
