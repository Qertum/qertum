namespace Qertum.Services;

/// <summary>One rule an issuance request failed.</summary>
public sealed class IssuancePolicyViolation
{
    /// <summary>Creates a violation.</summary>
    public IssuancePolicyViolation(string rule, string value, string message)
    {
        Rule = rule;
        Value = value;
        Message = message;
    }

    /// <summary>
    /// Rule identifier: <c>template</c>, <c>dnsSuffix</c>, <c>ipRange</c>, <c>keyAlgorithm</c>,
    /// <c>keyCapability</c> (a key that cannot sign under a template that issues a CA certificate),
    /// <c>maxValidity</c>, or <c>requesterRole</c> (the submitting caller holds none of the
    /// policy's allowed requester roles).
    /// </summary>
    public string Rule { get; }

    /// <summary>The offending value from the request.</summary>
    public string Value { get; }

    /// <summary>Human-readable explanation.</summary>
    public string Message { get; }
}

/// <summary>Request body for creating an issuance policy or changing its name and description.</summary>
public sealed class SaveIssuancePolicyRequest
{
    /// <summary>Unique display name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Optional description.</summary>
    public string? Description { get; init; }
}

/// <summary>Request body replacing every rule on a policy's draft. Empty lists mean unrestricted.</summary>
public sealed class SaveIssuancePolicyDraftRequest
{
    /// <summary>Allowed DNS suffixes, e.g. <c>corp.example.com</c>.</summary>
    public List<string> AllowedDnsSuffixes { get; init; } = [];

    /// <summary>Allowed CIDR ranges or single addresses for IP SANs.</summary>
    public List<string> AllowedIpRanges { get; init; } = [];

    /// <summary>Allowed canonical key algorithm strings, e.g. <c>ECDSA-P256</c>.</summary>
    public List<string> AllowedKeyAlgorithms { get; init; } = [];

    /// <summary>
    /// IdP roles allowed to submit requests under templates linked to this policy; empty means any
    /// role. Admin always passes. ACME, EST, renewals and approval are not role-checked.
    /// </summary>
    public List<string> AllowedRequesterRoles { get; init; } = [];

    /// <summary>
    /// Whether the CA may generate the key. <see cref="KeyCustodyMode.RequireClientGenerated"/>
    /// admits only CSR-carrying requests, which in practice means ACME or EST enrollment.
    /// </summary>
    public KeyCustodyMode KeyCustody { get; init; } = KeyCustodyMode.Any;

    /// <summary>Maximum validity in days; null for no ceiling.</summary>
    public int? MaxValidityDays { get; init; }
}

/// <summary>Request body naming the exact draft being published, as read by the publisher.</summary>
public sealed class PublishIssuancePolicyRequest
{
    /// <summary>Id of the draft version the publisher reviewed.</summary>
    public Guid DraftVersionId { get; init; }

    /// <summary>The draft's <c>UpdatedAtUtc</c> as the publisher read it.</summary>
    public DateTime DraftUpdatedAtUtc { get; init; }
}

/// <summary>One policy version as returned by the API.</summary>
public sealed class IssuancePolicyVersionResponse
{
    /// <summary>Version id.</summary>
    public Guid Id { get; init; }

    /// <summary>Sequential version number.</summary>
    public int VersionNumber { get; init; }

    /// <summary>Lifecycle state.</summary>
    public IssuancePolicyVersionStatus Status { get; init; }

    /// <summary>Allowed DNS suffixes.</summary>
    public IReadOnlyList<string> AllowedDnsSuffixes { get; init; } = [];

    /// <summary>Allowed IP ranges.</summary>
    public IReadOnlyList<string> AllowedIpRanges { get; init; } = [];

    /// <summary>Allowed key algorithms.</summary>
    public IReadOnlyList<string> AllowedKeyAlgorithms { get; init; } = [];

    /// <summary>IdP roles allowed to submit requests; empty means any role.</summary>
    public IReadOnlyList<string> AllowedRequesterRoles { get; init; } = [];

    /// <summary>Where the key must come from; <c>Any</c> means the CA may generate it.</summary>
    public KeyCustodyMode KeyCustody { get; init; } = KeyCustodyMode.Any;

    /// <summary>Maximum validity in days, or null.</summary>
    public int? MaxValidityDays { get; init; }

    /// <summary>Identity that opened the draft.</summary>
    public string CreatedBy { get; init; } = string.Empty;

    /// <summary>UTC creation time.</summary>
    public DateTime CreatedAtUtc { get; init; }

    /// <summary>UTC time of the last draft save; the publish token.</summary>
    public DateTime UpdatedAtUtc { get; init; }

    /// <summary>Publishing identity, or null.</summary>
    public string? PublishedBy { get; init; }

    /// <summary>UTC publish time, or null.</summary>
    public DateTime? PublishedAtUtc { get; init; }
}

/// <summary>Policy list entry.</summary>
public sealed class IssuancePolicySummaryResponse
{
    /// <summary>Policy id.</summary>
    public IssuancePolicyId Id { get; init; }

    /// <summary>Display name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Description.</summary>
    public string? Description { get; init; }

    /// <summary>Whether the policy is archived.</summary>
    public bool IsArchived { get; init; }

    /// <summary>Version number of the enforced version, or null when nothing is published.</summary>
    public int? PublishedVersionNumber { get; init; }

    /// <summary>Whether a draft exists.</summary>
    public bool HasDraft { get; init; }

    /// <summary>Number of templates linked to the policy.</summary>
    public int LinkedTemplateCount { get; init; }
}

/// <summary>A policy with its published and draft versions.</summary>
public sealed class IssuancePolicyResponse
{
    /// <summary>Policy id.</summary>
    public IssuancePolicyId Id { get; init; }

    /// <summary>Display name.</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>Description.</summary>
    public string? Description { get; init; }

    /// <summary>Whether the policy is archived.</summary>
    public bool IsArchived { get; init; }

    /// <summary>UTC creation time.</summary>
    public DateTime CreatedAtUtc { get; init; }

    /// <summary>UTC time of the last policy-level change.</summary>
    public DateTime UpdatedAtUtc { get; init; }

    /// <summary>The enforced version, or null.</summary>
    public IssuancePolicyVersionResponse? Published { get; init; }

    /// <summary>The draft, or null.</summary>
    public IssuancePolicyVersionResponse? Draft { get; init; }

    /// <summary>Type keys of templates linked to the policy.</summary>
    public IReadOnlyList<string> LinkedTemplateTypeKeys { get; init; } = [];
}
