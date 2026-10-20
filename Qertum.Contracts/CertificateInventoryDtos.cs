namespace Qertum.Services;

/// <summary>Read-only facts about one certificate issued by Qertum.</summary>
public sealed class CertificateInventoryItem
{
    /// <summary>Request that produced this certificate.</summary>
    public CertificateRequestId RequestId { get; init; }
    /// <summary>Request this certificate renewed, when applicable.</summary>
    public CertificateRequestId? RenewedFromId { get; init; }
    /// <summary>The issuer that signed this certificate, when known (older rows resolve to the legacy issuer).</summary>
    public IssuerId? IssuerId { get; init; }
    /// <summary>Display name of <see cref="IssuerId"/>, when the issuer is registered.</summary>
    public string? IssuerName { get; init; }
    /// <summary>Primary or PQC leg of a paired request.</summary>
    public string Leg { get; init; } = "primary";
    /// <summary>Certificate type recorded on the request.</summary>
    public string? Type { get; init; }
    /// <summary>Current request status, including revocation state.</summary>
    public CertificateRequestStatus Status { get; init; }
    /// <summary>Immutable owner subject, or null for older requests.</summary>
    public string? OwnerSubject { get; init; }
    /// <summary>Requester display name, which is not an ownership proof.</summary>
    public string OwnerDisplay { get; init; } = string.Empty;
    /// <summary>Certificate serial as uppercase hexadecimal, or null when parsing failed.</summary>
    public string? SerialNumber { get; init; }
    /// <summary>Certificate subject distinguished name, or null when parsing failed.</summary>
    public string? SubjectDn { get; init; }
    /// <summary>Certificate issuer distinguished name, or null when parsing failed.</summary>
    public string? IssuerDn { get; init; }
    /// <summary>Actual subject public-key algorithm, or Unknown.</summary>
    public string SubjectKeyAlgorithm { get; init; } = "Unknown";
    /// <summary>Algorithm named by the certificate signature OID, or Unknown.</summary>
    public string IssuerSignatureAlgorithm { get; init; } = "Unknown";
    /// <summary>Raw signature algorithm OID, or null when parsing failed.</summary>
    public string? IssuerSignatureOid { get; init; }
    /// <summary>Key algorithm of the verified current root, or null without that evidence.</summary>
    public string? CurrentRootKeyAlgorithm { get; init; }
    /// <summary>Distinguished name of the verified current root, or null without that evidence.</summary>
    public string? CurrentRootSubjectDn { get; init; }
    /// <summary>SHA-256 fingerprint of the verified current root, or null without that evidence.</summary>
    public string? CurrentRootSha256Fingerprint { get; init; }
    /// <summary>SignatureVerifiedWithCurrentRoot (the leaf verifies under the CA that issued it and that CA's root self-verifies) or Unknown; no wider path claim is made.</summary>
    public string ChainStatus { get; init; } = "Unknown";
    /// <summary>Parsed or InvalidCertificate.</summary>
    public string AnalysisStatus { get; init; } = "InvalidCertificate";
    /// <summary>Reason certificate facts are incomplete, or null when analysis succeeded.</summary>
    public string? AnalysisError { get; init; }
    /// <summary>Actual certificate start, or null when parsing failed.</summary>
    public DateTime? ValidFromUtc { get; init; }
    /// <summary>Actual certificate expiry, or null when parsing failed.</summary>
    public DateTime? ValidToUtc { get; init; }
    /// <summary>Unknown until installed software and its validation behavior are tracked.</summary>
    public string DeploymentCompatibility { get; init; } = "Unknown";
    /// <summary>Recorded facts about the certificate; every field null means Unknown.</summary>
    public CertificateMetadata Metadata { get; init; } = new();
}
