namespace Qertum.Services;

/// <summary>One ACME order in the operator's list.</summary>
public sealed class AcmeOrderSummary
{
    /// <summary>Order id.</summary>
    public Guid Id { get; init; }

    /// <summary>The ACME account that placed it.</summary>
    public Guid AccountId { get; init; }

    /// <summary>The names ordered, as the client sent them.</summary>
    public List<string> Identifiers { get; init; } = [];

    /// <summary>Status as reported to the client, with expiry applied.</summary>
    public string Status { get; init; } = string.Empty;

    /// <summary>When the order was created (UTC).</summary>
    public DateTime CreatedAtUtc { get; init; }

    /// <summary>When the order expires (UTC).</summary>
    public DateTime ExpiresAtUtc { get; init; }

    /// <summary>The certificate request <c>finalize</c> filed, once it has.</summary>
    public Guid? CertificateRequestId { get; init; }

    /// <summary>Category of the most recent failed challenge attempt, if any.</summary>
    public string? LastFailureCategory { get; init; }

    /// <summary>Detail of the most recent failed challenge attempt, if any.</summary>
    public string? LastFailureDetail { get; init; }

    /// <summary>When the most recent failed challenge attempt happened (UTC).</summary>
    public DateTime? LastFailureAtUtc { get; init; }
}

/// <summary>One challenge of an authorization. The token is deliberately absent.</summary>
public sealed class AcmeChallengeView
{
    /// <summary><c>http-01</c> or <c>dns-01</c>.</summary>
    public string Type { get; init; } = string.Empty;

    /// <summary>Challenge status.</summary>
    public string Status { get; init; } = string.Empty;

    /// <summary>Validation attempts so far.</summary>
    public int Attempts { get; init; }

    /// <summary>When the next attempt is due, while one is scheduled (UTC).</summary>
    public DateTime? NextAttemptAfterUtc { get; init; }

    /// <summary>When it was validated (UTC).</summary>
    public DateTime? ValidatedAtUtc { get; init; }
}

/// <summary>One authorization of an order.</summary>
public sealed class AcmeAuthorizationView
{
    /// <summary>The base name; a wildcard is marked by <see cref="Wildcard"/>.</summary>
    public string Identifier { get; init; } = string.Empty;

    /// <summary>Whether the client ordered <c>*.</c> this name.</summary>
    public bool Wildcard { get; init; }

    /// <summary>Status with expiry applied.</summary>
    public string Status { get; init; } = string.Empty;

    /// <summary>When the authorization expires (UTC).</summary>
    public DateTime ExpiresAtUtc { get; init; }

    /// <summary>The challenges offered for it.</summary>
    public List<AcmeChallengeView> Challenges { get; init; } = [];
}

/// <summary>An order with its authorizations and diagnostic history.</summary>
public sealed class AcmeOrderDetail
{
    /// <summary>The order.</summary>
    public AcmeOrderSummary Order { get; init; } = new();

    /// <summary>Its authorizations.</summary>
    public List<AcmeAuthorizationView> Authorizations { get; init; } = [];

    /// <summary>Diagnostic events for the order, oldest first, with hints.</summary>
    public List<TimelineEntry> History { get; init; } = [];
}
