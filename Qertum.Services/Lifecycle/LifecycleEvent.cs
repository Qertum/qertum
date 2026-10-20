namespace Qertum.Services.Lifecycle;

/// <summary>
/// One row of the indexed event table behind the certificate timeline and enrollment diagnostics.
/// </summary>
/// <remarks>
/// The table is a derived copy for reading. The CLEF audit file stays the record; a row is written by
/// <see cref="LifecycleEventTableSink"/> only, never by a call site. For audit events <see cref="Id"/>
/// is the audit entry's <c>AuditEntryId</c>, so the row points at its exact file line and a retried
/// batch cannot insert it twice.
/// </remarks>
public sealed class LifecycleEvent
{
    public Guid Id { get; init; }
    public string Kind { get; init; } = LifecycleEventKinds.Audit;
    public DateTime OccurredAtUtc { get; init; }
    public string SubjectType { get; init; } = string.Empty;
    public Guid SubjectId { get; init; }
    public string Action { get; init; } = string.Empty;
    public string? Category { get; init; }
    public string PerformedBy { get; init; } = string.Empty;
    public string? Detail { get; init; }
    public string? DataJson { get; init; }
    public string? TraceId { get; init; }
}

/// <summary>Values of <see cref="LifecycleEvent.Kind"/>.</summary>
public static class LifecycleEventKinds
{
    /// <summary>A copy of an audit event: something a person or the pipeline did.</summary>
    public const string Audit = "Audit";

    /// <summary>An operational event (a challenge retry, a refused login). Never in the audit file.</summary>
    public const string Diagnostic = "Diagnostic";
}

/// <summary>Values of <see cref="LifecycleEvent.SubjectType"/>.</summary>
public static class LifecycleSubjectTypes
{
    public const string CertificateRequest = "CertificateRequest";
    public const string AcmeOrder = "AcmeOrder";
    public const string AcmeAccount = "AcmeAccount";
    public const string EstCredential = "EstCredential";
    public const string CertificateTemplate = "CertificateTemplate";
    public const string IssuancePolicy = "IssuancePolicy";
    public const string AcmeExternalAccountKey = "AcmeExternalAccountKey";
    public const string WebhookDestinationRule = "WebhookDestinationRule";
    public const string BackgroundJob = "BackgroundJob";
    public const string Issuer = "Issuer";
    public const string PqcException = "PqcException";
    public const string BulkOperation = "BulkOperation";
    public const string Approval = "Approval";

}
