using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>Lifecycle state of an <see cref="IssuancePolicyVersion"/>.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IssuancePolicyVersionStatus
{
    /// <summary>Editable; not enforced.</summary>
    Draft = 0,

    /// <summary>The enforced version. Immutable.</summary>
    Published = 1,

    /// <summary>A formerly published version. Immutable; kept for history.</summary>
    Superseded = 2
}

/// <summary>
/// Where the key of a certificate issued under an <see cref="IssuancePolicy"/> may come from.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum KeyCustodyMode
{
    /// <summary>No custody restriction: the CA may generate and store the key.</summary>
    Any = 0,

    /// <summary>
    /// The requester must hold the key: the request has to carry a CSR, so the CA never sees a
    /// private key and has none to export. Only ACME finalize and EST enrollment carry one, so a
    /// policy set to this cannot be satisfied over REST, the web wizard or the CLI.
    /// </summary>
    RequireClientGenerated = 1
}

/// <summary>One set of rules for an <see cref="IssuancePolicy"/>. Only a draft may change.</summary>
public sealed class IssuancePolicyVersion
{
    /// <summary>Unique identifier. Recorded on requests as <see cref="CertificateRequest.PolicyVersionId"/>.</summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>The policy this version belongs to.</summary>
    public IssuancePolicyId PolicyId { get; set; }

    /// <summary>Sequential version number, unique within the policy.</summary>
    public int VersionNumber { get; set; }

    /// <summary>Lifecycle state.</summary>
    public IssuancePolicyVersionStatus Status { get; set; } = IssuancePolicyVersionStatus.Draft;

    /// <summary>JSON array of allowed DNS suffixes. Empty means unrestricted.</summary>
    public string AllowedDnsSuffixesJson { get; set; } = "[]";

    /// <summary>JSON array of allowed CIDR ranges for IP SANs. Empty means unrestricted.</summary>
    public string AllowedIpRangesJson { get; set; } = "[]";

    /// <summary>JSON array of allowed canonical key algorithm strings. Empty means unrestricted.</summary>
    public string AllowedKeyAlgorithmsJson { get; set; } = "[]";

    /// <summary>
    /// JSON array of IdP role names allowed to submit requests (REST/Web/CLI) under templates
    /// linked to this policy. Empty = any role. ACME, EST, renewals and approval are not checked.
    /// </summary>
    public string AllowedRequesterRolesJson { get; set; } = "[]";

    /// <summary>
    /// Whether the CA may generate the key, or the requester must supply one in a CSR. Defaults to
    /// <see cref="KeyCustodyMode.Any"/>, so an existing policy keeps issuing as before.
    /// </summary>
    public KeyCustodyMode KeyCustody { get; set; } = KeyCustodyMode.Any;

    /// <summary>Maximum certificate validity in days. Null means no policy ceiling.</summary>
    public int? MaxValidityDays { get; set; }

    /// <summary>Identity that opened the draft.</summary>
    public string CreatedBy { get; set; } = string.Empty;

    /// <summary>UTC timestamp when the draft was opened.</summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>UTC timestamp of the last draft save. Publish must present this value unchanged.</summary>
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>Identity that published the version. Null until published.</summary>
    public string? PublishedBy { get; set; }

    /// <summary>UTC timestamp of publication. Null until published.</summary>
    public DateTime? PublishedAtUtc { get; set; }
}
