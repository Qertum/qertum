namespace Qertum.Services;

/// <summary>Defines the X.509 profile for a class of certificates (e.g. Web Server, Client Auth).</summary>
public sealed class CertificateTemplate
{
    /// <summary>Unique identifier for the template.</summary>
    public CertificateTemplateId Id { get; set; } = Guid.NewGuid();

    /// <summary>Human-readable display name shown in the UI and certificate type dropdown.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Machine key stored on CertificateRequest.Type. Immutable for built-in templates.</summary>
    public string TypeKey { get; set; } = string.Empty;

    /// <summary>Optional description of what this certificate type is used for.</summary>
    public string? Description { get; set; }

    /// <summary>When true the template cannot be deleted and its TypeKey cannot be changed.</summary>
    public bool IsBuiltIn { get; set; }

    /// <summary>JSON array of key-usage flag names, e.g. ["DigitalSignature","KeyEncipherment"].</summary>
    public string KeyUsagesJson { get; set; } = "[]";

    /// <summary>JSON array of Extended Key Usage OID strings, e.g. ["1.3.6.1.5.5.7.3.1"].</summary>
    public string ExtendedKeyUsagesJson { get; set; } = "[]";

    /// <summary>JSON array of SAN type names: "dns", "ip", "email", "upn".</summary>
    public string SanTypesJson { get; set; } = "[]";

    /// <summary>JSON array of {Oid, Value, Critical} for arbitrary X.509 v3 extensions.</summary>
    public string? CustomExtensionsJson { get; set; }

    /// <summary>Overrides global CertificateValidityDays when set. Null = use global setting.</summary>
    public int? ValidityDays { get; set; }

    /// <summary>
    /// The issuance policy governing requests of this type. Null means unrestricted. Changing it
    /// requires the <c>policies.publish</c> permission.
    /// </summary>
    public IssuancePolicyId? IssuancePolicyId { get; set; }

    /// <summary>
    /// The issuer that signs this template's certificates; null = the default issuer. Changed only
    /// through <c>PUT /v1/certificate-templates/{id}/issuer</c>, never by a template save.
    /// </summary>
    public IssuerId? IssuerId { get; set; }

    /// <summary>UTC timestamp when the template was created.</summary>
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>UTC timestamp of the last modification.</summary>
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// PQC stage for this template; null uses <see cref="CaSettings.PqcStage"/>. Set only through
    /// <c>PUT /v1/certificate-templates/{id}/pqc-stage</c>, never on the save DTO.
    /// </summary>
    public PqcStage? PqcStageOverride { get; set; }
}
