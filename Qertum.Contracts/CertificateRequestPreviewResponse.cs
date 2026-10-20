namespace Qertum.Services;

/// <summary>
/// What would happen if this request were submitted. Advisory only: every check is made again for
/// real at create, approval and issuance, so a preview is never an authorization step.
/// </summary>
public sealed class CertificateRequestPreviewResponse
{
    /// <summary>Whether the request would be accepted right now.</summary>
    public bool Allowed { get; init; }

    /// <summary>Every rule the request would fail, not only the first.</summary>
    public IReadOnlyList<IssuancePolicyViolation> Violations { get; init; } = [];

    /// <summary>Name of the policy governing the request's template, or null when none does.</summary>
    public string? PolicyName { get; init; }

    /// <summary>Version number of the policy version that would be enforced.</summary>
    public int? PolicyVersionNumber { get; init; }

    /// <summary>Id of the policy version that would be enforced.</summary>
    public Guid? PolicyVersionId { get; init; }

    /// <summary>The template type key the request names.</summary>
    public string TemplateTypeKey { get; init; } = string.Empty;

    /// <summary>Whether a template exists for that type key.</summary>
    public bool TemplateExists { get; init; }

    /// <summary>Validity the issued certificate would get, or 0 when no template exists.</summary>
    public int EffectiveValidityDays { get; init; }

    /// <summary>Canonical key algorithm string the certificate would use, with the default resolved.</summary>
    public string EffectiveKeyAlgorithm { get; init; } = string.Empty;

    /// <summary>Warnings the same request would return on create, for example a classical key under a PQC warning stage. Empty when none.</summary>
    public IReadOnlyList<string> Warnings { get; init; } = [];
}
