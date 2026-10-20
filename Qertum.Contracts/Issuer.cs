using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>Where an issuer sits in the hierarchy.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IssuerKind
{
    /// <summary>Self-signed trust anchor.</summary>
    Root,

    /// <summary>CA certificate signed by another issuer.</summary>
    Intermediate
}

/// <summary>Whether this server holds the issuer's private key.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IssuerKeyCustody
{
    /// <summary>The key is on this server, encrypted with the Data Protection key ring, and signs here.</summary>
    Online,

    /// <summary>The key is kept elsewhere (offline root); this server only holds the certificate.</summary>
    Offline
}

/// <summary>Issuer lifecycle state, stored as its name.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum IssuerStatus
{
    /// <summary>Key and request file exist; waiting for the signed certificate to be installed.</summary>
    PendingCertificate,

    /// <summary>Issues certificates (online) or anchors a path (offline) and answers revocation.</summary>
    Active,

    /// <summary>Issues nothing new but still answers CRL and OCSP for what it issued.</summary>
    Retired,

    /// <summary>Retired and nothing it issued is unexpired; its key is deleted. Kept as history.</summary>
    Archived,

    /// <summary>Replaced by force; its key and certificate files are deleted and its certificates can no longer be revoked.</summary>
    Destroyed
}

/// <summary>
/// One certificate authority known to this server: a root or an intermediate, online or offline.
/// Never carries key material — an online issuer's key lives in an encrypted file under
/// <c>CaData</c>, an offline issuer's key is not on the server at all.
/// </summary>
public sealed class Issuer
{
    /// <summary>Issuer identifier.</summary>
    public IssuerId Id { get; set; } = new(Guid.NewGuid());

    /// <summary>Unique display name.</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>Root or intermediate.</summary>
    public IssuerKind Kind { get; set; }

    /// <summary>The issuer that signed this one's certificate; null for roots.</summary>
    public IssuerId? ParentIssuerId { get; set; }

    /// <summary>Whether the key is on this server.</summary>
    public IssuerKeyCustody KeyCustody { get; set; }

    /// <summary>Lifecycle state.</summary>
    public IssuerStatus Status { get; set; }

    /// <summary>The issuer that signs when a template names none. At most one row; always Active and Online.</summary>
    public bool IsDefault { get; set; }

    /// <summary>
    /// True for the issuer stored in the pre-hierarchy files <c>CaData/ca.key</c> + <c>ca.pem</c>
    /// ("legacy issuer"). Its CRL counters stay in <see cref="CaSettings"/>, and issued rows with a
    /// null <see cref="CertificateRequest.IssuerId"/> belong to it.
    /// </summary>
    public bool LegacyFiles { get; set; }

    /// <summary>The issuer's certificate; null only while <see cref="IssuerStatus.PendingCertificate"/>.</summary>
    public string? CertificatePem { get; set; }

    /// <summary>The PKCS#10 request a pending intermediate asked its parent to sign; kept after install for audit.</summary>
    public string? CsrPem { get; set; }

    /// <summary>The issuer key's algorithm, detected exactly from the key.</summary>
    public CertificateKeyAlgorithm? KeyAlgorithm { get; set; }

    /// <summary>Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo. Unique: one row per key.</summary>
    public string SpkiSha256 { get; set; } = string.Empty;

    /// <summary>Subject DN parsed from the certificate (or requested, while pending).</summary>
    public string? SubjectDn { get; set; }

    /// <summary>Uppercase hex serial of <see cref="CertificatePem"/>.</summary>
    public string? SerialNumber { get; set; }

    /// <summary>Lowercase hex SubjectKeyIdentifier.</summary>
    public string? SubjectKeyIdentifier { get; set; }

    /// <summary>Certificate notBefore (UTC).</summary>
    public DateTime? ValidFrom { get; set; }

    /// <summary>Certificate notAfter (UTC).</summary>
    public DateTime? ValidTo { get; set; }

    /// <summary>BasicConstraints pathLenConstraint; null = unlimited.</summary>
    public int? PathLengthConstraint { get; set; }

    /// <summary>NameConstraints permitted DNS subtrees as a JSON string array; <c>[]</c> = none.</summary>
    public string PermittedDnsSuffixesJson { get; set; } = "[]";

    /// <summary>NameConstraints excluded DNS subtrees as a JSON string array.</summary>
    public string ExcludedDnsSuffixesJson { get; set; } = "[]";

    /// <summary>NameConstraints permitted IP subtrees (CIDR) as a JSON string array.</summary>
    public string PermittedIpRangesJson { get; set; } = "[]";

    /// <summary>NameConstraints excluded IP subtrees (CIDR) as a JSON string array.</summary>
    public string ExcludedIpRangesJson { get; set; } = "[]";

    /// <summary>Pending intermediates: the request file's constraint block, checked again at install.</summary>
    public string? RequestedConstraintsJson { get; set; }

    /// <summary>Last CRL number claimed (non-legacy issuers; the legacy issuer uses <see cref="CaSettings.CrlNumber"/>).</summary>
    public long CrlNumber { get; set; }

    /// <summary>Delta-CRL base number (non-legacy issuers).</summary>
    public long? BaseCrlNumber { get; set; }

    /// <summary>Delta-CRL base thisUpdate (non-legacy issuers).</summary>
    public DateTime? BaseCrlThisUpdateUtc { get; set; }

    /// <summary>Offline issuers: the CRL uploaded by the operator, served as-is.</summary>
    [JsonIgnore]
    public byte[]? UploadedCrlDer { get; set; }

    /// <summary>CRL number of <see cref="UploadedCrlDer"/>.</summary>
    public long? UploadedCrlNumber { get; set; }

    /// <summary>nextUpdate of <see cref="UploadedCrlDer"/>.</summary>
    public DateTime? UploadedCrlNextUpdateUtc { get; set; }

    /// <summary>CDP written into certificates this issuer signs; null = derived default.</summary>
    public string? CrlDistributionPoint { get; set; }

    /// <summary>OCSP URL written into certificates this issuer signs; null = derived default.</summary>
    public string? OcspResponderUrl { get; set; }

    /// <summary>caIssuers URL written into certificates this issuer signs; null = derived default.</summary>
    public string? CaIssuersUrl { get; set; }

    /// <summary>Row creation (UTC).</summary>
    public DateTime CreatedAtUtc { get; set; }

    /// <summary>When the issuer became Active (UTC).</summary>
    public DateTime? ActivatedAtUtc { get; set; }

    /// <summary>When the issuer was retired (UTC).</summary>
    public DateTime? RetiredAtUtc { get; set; }

    /// <summary>When the issuer was archived (UTC).</summary>
    public DateTime? ArchivedAtUtc { get; set; }

    /// <summary>When the issuer was destroyed by a force replace (UTC).</summary>
    public DateTime? DestroyedAtUtc { get; set; }
}
