namespace Qertum.Services;

/// <summary>
/// A named issuance policy that certificate templates reference. The rules themselves live on its
/// <see cref="IssuancePolicyVersion"/> rows; only the published version is enforced.
/// </summary>
public sealed class IssuancePolicy
{
    /// <summary>Unique identifier.</summary>
    public IssuancePolicyId Id { get; set; } = Guid.NewGuid();

    /// <summary>Unique display name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Optional description of what the policy is for.</summary>
    public string? Description { get; set; }

    /// <summary>Archived policies cannot be drafted, published, or linked to a template.</summary>
    public bool IsArchived { get; set; }

    /// <summary>UTC timestamp when the policy was created.</summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>UTC timestamp of the last change to name, description, or archive state.</summary>
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>Every version of the policy: at most one draft, at most one published, any number superseded.</summary>
    public List<IssuancePolicyVersion> Versions { get; set; } = [];
}
