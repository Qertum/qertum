using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>What a PQC stage would do to one classical certificate or request.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum PqcVerdictKind
{
    /// <summary>Accepted; at Observe an event is recorded, at Off nothing is.</summary>
    Allowed,
    /// <summary>Accepted, and the requester is warned where the protocol has a channel.</summary>
    Warned,
    /// <summary>Would be refused, but an active exception admits it.</summary>
    CoveredByException,
    /// <summary>Would be refused.</summary>
    Refused
}

/// <summary>Query of <c>GET /v1/pqc/migration-report</c>.</summary>
public sealed class PqcReportQuery
{
    /// <summary>Limit the report to one template; null reports every template.</summary>
    public string? TemplateTypeKey { get; init; }

    /// <summary>Judge under this stage instead of each template's current one; null reports today's rules.</summary>
    public PqcStage? ProposedStage { get; init; }

    /// <summary>How many days of observed traffic to count, 1 to 365; clamped to diagnostic retention.</summary>
    public int ObservedDays { get; init; } = 30;

    /// <summary>1-based page of items.</summary>
    public int Page { get; init; } = 1;

    /// <summary>Items per page, 1 to 500.</summary>
    public int PageSize { get; init; } = 50;

    /// <summary>The reason this query is unusable, or null when it is fine.</summary>
    public string? Validate()
    {
        if (ProposedStage is { } stage && !Enum.IsDefined(stage))
            return $"proposedStage must be one of {string.Join(", ", Enum.GetNames<PqcStage>())}.";
        if (ObservedDays is < 1 or > 365) return "observedDays must be between 1 and 365.";
        if (Page < 1) return "page must be 1 or more.";
        if (PageSize is < 1 or > 500) return "pageSize must be between 1 and 500.";
        return null;
    }

    /// <summary>The same query for another page.</summary>
    public PqcReportQuery WithPage(int page, int pageSize) => new()
    {
        TemplateTypeKey = TemplateTypeKey, ProposedStage = ProposedStage, ObservedDays = ObservedDays,
        Page = page, PageSize = pageSize
    };
}

/// <summary>One template's row of the report: its stages and what the live population looks like under them.</summary>
public sealed class PqcTemplateReport
{
    /// <summary>Template type key, or the request type of rows that have no template.</summary>
    public string TypeKey { get; init; } = "";

    /// <summary>Template name; "(no template)" for a type without one.</summary>
    public string Name { get; init; } = "";

    /// <summary>The stage in force today.</summary>
    public PqcStage CurrentStage { get; init; }

    /// <summary>The stage judged: the proposal, or <see cref="CurrentStage"/> when none was given.</summary>
    public PqcStage ProposedStage { get; init; }

    /// <summary>Unexpired issued certificates (requests, not legs).</summary>
    public int LiveTotal { get; init; }

    /// <summary>Live certificates whose key is post-quantum, paired, composite or ML-KEM.</summary>
    public int Compliant { get; init; }

    /// <summary>Live classical certificates a renewal would accept without a warning.</summary>
    public int ClassicalAllowed { get; init; }

    /// <summary>Live classical certificates a renewal would accept with a warning.</summary>
    public int ClassicalWarned { get; init; }

    /// <summary>Live classical certificates a renewal would refuse.</summary>
    public int ClassicalRefused { get; init; }

    /// <summary>Live classical certificates a renewal would refuse but an exception admits.</summary>
    public int ClassicalCoveredByException { get; init; }

    /// <summary>Live certificates with no stored key algorithm, judged as RSA the way a renewal is.</summary>
    public int AlgorithmAssumed { get; init; }

    /// <summary>Pending and Approved requests of this type.</summary>
    public int InFlight { get; init; }

    /// <summary>Expired, revoked or pending-revocation certificates of this type, outside the live population.</summary>
    public int NotAffected { get; init; }
}

/// <summary>One live certificate or in-flight request with a classical key.</summary>
public sealed class PqcReportItem
{
    /// <summary>The request id.</summary>
    public CertificateRequestId RequestId { get; init; }

    /// <summary>Common name.</summary>
    public string CommonName { get; init; } = "";

    /// <summary>Template type key of the request.</summary>
    public string TemplateTypeKey { get; init; } = "";

    /// <summary>When the certificate expires; null for a request that has none yet.</summary>
    public DateTime? ValidToUtc { get; init; }

    /// <summary>Request status: Issued, Pending or Approved.</summary>
    public CertificateRequestStatus Status { get; init; }

    /// <summary>Stored key algorithm, canonical name; <c>RSA</c> when <see cref="AlgorithmAssumed"/>.</summary>
    public string KeyAlgorithm { get; init; } = "";

    /// <summary>True when the row stores no algorithm and this one is what a renewal would assume.</summary>
    public bool AlgorithmAssumed { get; init; }

    /// <summary>What the judged stage would do.</summary>
    public PqcVerdictKind Verdict { get; init; }

    /// <summary>The evaluator's reason; null when nothing is said.</summary>
    public string? Reason { get; init; }

    /// <summary>The exception that admits it, for <see cref="PqcVerdictKind.CoveredByException"/>.</summary>
    public PqcExceptionId? ExceptionId { get; init; }

    /// <summary>True when judged as a renewal (every live certificate, and in-flight requests that renew one).</summary>
    public bool IsRenewal { get; init; }

    /// <summary>True for a Pending or Approved request, false for a live certificate.</summary>
    public bool InFlight { get; init; }

    /// <summary>
    /// The inventory's separate facts (subject key, issuer signature, path status) per certificate leg;
    /// empty for a request without a certificate. Filled for the returned page only.
    /// </summary>
    public IReadOnlyList<CertificateInventoryItem> Certificates { get; init; } = [];
}

/// <summary>Counts of one kind of stage event for one template and source.</summary>
public sealed class PqcObservedCount
{
    /// <summary>Template type key, or <c>unknown</c> when the request row no longer exists.</summary>
    public string TemplateTypeKey { get; init; } = "";

    /// <summary>Where the request came from: acme, est, est-cert, rest or unknown.</summary>
    public string Source { get; init; } = "";

    /// <summary>Observed, Warned or ExceptionApplied.</summary>
    public string Kind { get; init; } = "";

    /// <summary>Events in the window.</summary>
    public int Count { get; init; }

    /// <summary>Distinct identities behind those events.</summary>
    public int DistinctIdentities { get; init; }
}

/// <summary>Observed stage events over a window that never exceeds what diagnostics retain.</summary>
public sealed class PqcObservedTraffic
{
    /// <summary>The window the caller asked for.</summary>
    public int RequestedDays { get; init; }

    /// <summary>The window counted: the smaller of the requested days and the retention.</summary>
    public int EffectiveDays { get; init; }

    /// <summary>How long diagnostic events are kept (<c>LifecycleEvents:DiagnosticRetentionDays</c>).</summary>
    public int RetentionDays { get; init; }

    /// <summary>Start of the counted window.</summary>
    public DateTime SinceUtc { get; init; }

    /// <summary>All events counted.</summary>
    public int TotalEvents { get; init; }

    /// <summary>Distinct identities across all events.</summary>
    public int DistinctIdentities { get; init; }

    /// <summary>The counts per template, source and kind.</summary>
    public IReadOnlyList<PqcObservedCount> Counts { get; init; } = [];
}

/// <summary>Response of <c>GET /v1/pqc/migration-report</c>.</summary>
public sealed class PqcMigrationReportResponse
{
    /// <summary>When the report was computed.</summary>
    public DateTime GeneratedAtUtc { get; init; }

    /// <summary>The CA-wide default stage today.</summary>
    public PqcStage CaDefaultStage { get; init; }

    /// <summary>The proposal that was judged; null when the report shows today's rules.</summary>
    public PqcStage? ProposedStage { get; init; }

    /// <summary>One entry per template (and per type without a template) in scope.</summary>
    public IReadOnlyList<PqcTemplateReport> Templates { get; init; } = [];

    /// <summary>A page of classical live certificates and in-flight requests, refused first.</summary>
    public PagedResult<PqcReportItem> Items { get; init; } = new();

    /// <summary>Observed traffic; null when withheld from this caller.</summary>
    public PqcObservedTraffic? Observed { get; init; }

    /// <summary>Sections left out for this caller. Always names <c>observed</c> when the block is absent.</summary>
    public IReadOnlyList<string> Withheld { get; init; } = [];

    /// <summary>The same report with another set of items (the CLI merges pages this way).</summary>
    public PqcMigrationReportResponse WithItems(PagedResult<PqcReportItem> items) => new()
    {
        GeneratedAtUtc = GeneratedAtUtc, CaDefaultStage = CaDefaultStage, ProposedStage = ProposedStage,
        Templates = Templates, Items = items, Observed = Observed, Withheld = Withheld
    };
}

/// <summary>The one wording of what the report does and does not say, shared by the Web page and the CLI.</summary>
public static class PqcMigrationReportNotes
{
    /// <summary>Scope note printed with every report.</summary>
    public const string Scope =
        "Every figure describes what would happen if the certificate were renewed, or the request approved, today "
        + "under the stage shown. It says nothing about whether the software that uses a certificate can handle its key. "
        + "Counts are of requests; a paired request counts once. The subject key, issuer signature and path facts are the "
        + "inventory's: SignatureVerifiedWithCurrentRoot means only that the leaf signature and the current root's "
        + "self-signature verified, and any other issuer path stays Unknown. Observed counts cover only the days "
        + "diagnostic events are kept.";
}
