using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace Qertum.Services;

/// <summary>EF entity representing a certificate request and its full lifecycle state.</summary>
public sealed class CertificateRequest
{
    /// <summary>Unique identifier for the request.</summary>
    public CertificateRequestId Id { get; init; } = Guid.NewGuid();

    /// <summary>X.509 Common Name (CN) requested for the certificate.</summary>
    public string CommonName { get; set; } = string.Empty;

    /// <summary>Identity of the user or service that submitted the request.</summary>
    public string RequestedBy { get; set; } = string.Empty;

    /// <summary>
    /// Stable subject identifier (the <c>sub</c> claim) of the principal that submitted the request.
    /// Used as the authorization key for private-key retrieval, because <see cref="RequestedBy"/> is a
    /// mutable display string. Null for rows created before this field existed; those rows require
    /// administrator access for private-key retrieval.
    /// </summary>
    public string? RequestedBySubject { get; set; }

    /// <summary>Current lifecycle status of the request.</summary>
    public CertificateRequestStatus Status { get; set; } = CertificateRequestStatus.Pending;

    /// <summary>UTC timestamp when the request was created.</summary>
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;

    /// <summary>UTC timestamp of the last status change.</summary>
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// The date/time (UTC) from which the issued certificate is valid. Null until the certificate is issued.
    /// </summary>
    public DateTime? ValidFrom { get; set; }

    /// <summary>
    /// The date/time (UTC) until which the issued certificate is valid. Null until the certificate is issued.
    /// </summary>
    public DateTime? ValidTo { get; set; }

    /// <summary>
    /// The date/time (UTC) when the certificate was revoked. Null unless the certificate has been revoked.
    /// </summary>
    public DateTime? RevokedAtUtc { get; set; }

    /// <summary>Certificate type, e.g. "WebServer" or "Client".</summary>
    public string? Type { get; set; } = "WebServer";

    /// <summary>JSON bag for type-specific properties such as SAN lists.</summary>
    public string? PropertiesJson { get; set; } = "{}";

    /// <summary>PEM-encoded certificate. Null until the certificate is issued.</summary>
    public string? CertificatePem { get; set; }

    /// <summary>
    /// PEM-encoded (encrypted at rest) private key. Null until the certificate is issued.
    /// Never serialized: key material is retrievable only through the owner-gated
    /// <c>GET /v1/certificate-requests/{id}/private-key</c> endpoint.
    /// </summary>
    [JsonIgnore]
    public string? PrivateKeyPem { get; set; }

    /// <summary>
    /// Uppercase hex serial number of the issued certificate. Null until the certificate is issued,
    /// and for rows issued before this field existed. Uniquely indexed: a CA must never sign two
    /// certificates under one serial, and the index is what turns a collision into a failed save
    /// rather than a silent misissuance. Set by the issuing pipeline only — never caller-supplied.
    /// </summary>
    public string? SerialNumber { get; set; }

    /// <summary>
    /// Uppercase hex serial number of the PQC certificate in <see cref="PqcCertificatePem"/>, for
    /// paired issuance only (a hybrid pair or a signing + encryption pair); null otherwise. The pair is two certificates with two serials,
    /// and OCSP finds a certificate by its serial, so the PQC one must be stored as well or the
    /// responder cannot answer for it. Uniquely indexed and pipeline-written only, the same rules as
    /// <see cref="SerialNumber"/>.
    /// </summary>
    public string? PqcSerialNumber { get; set; }

    /// <summary>Human-readable reason supplied when revoking the certificate.</summary>
    public string? RevocationReason { get; set; }

    /// <summary>ID of the request this one was renewed from, if applicable.</summary>
    public CertificateRequestId? RenewedFromId { get; init; }

    /// <summary>
    /// Facts recorded about the certificate (owner team, contact, purpose, target system, ticket,
    /// compatibility). Never null; all-null means everything is Unknown. A renewal starts with a copy.
    /// </summary>
    public CertificateMetadata Metadata { get; set; } = new();

    /// <summary>Key and signature algorithm for the leaf certificate. Defaults to <see cref="CertificateKeyAlgorithm.Rsa"/> when null.</summary>
    public CertificateKeyAlgorithm? KeyAlgorithm { get; set; }

    /// <summary>
    /// PEM-encoded second certificate of a paired request: the PQC certificate of a hybrid pair, or the
    /// ML-KEM encryption certificate of a signing + encryption pair. Null for unpaired requests.
    /// </summary>
    public string? PqcCertificatePem { get; set; }

    /// <summary>
    /// PEM-encoded private key of the second certificate of a paired request (see <see cref="PqcCertificatePem"/>). Null for unpaired requests.
    /// Never serialized, for the same reason as <see cref="PrivateKeyPem"/>.
    /// </summary>
    [JsonIgnore]
    public string? PqcPrivateKeyPem { get; set; }

    /// <summary>
    /// Human-readable reason recorded when the queue consumer permanently rejects the request after exhausting retries.
    /// Null for requests rejected by a human operator.
    /// </summary>
    public string? FailureReason { get; set; }

    /// <summary>
    /// Whether a private key is held server-side for this request. Lets clients decide whether to offer
    /// a key or PKCS#12 download without the key itself ever being serialized. False for ACME-issued
    /// requests, where the client generated the key and the CA never saw it.
    /// </summary>
    [NotMapped]
    public bool HasPrivateKey { get; set; }

    /// <summary>
    /// Warnings raised while creating, updating or renewing this request, for example a classical key
    /// under a PQC warning stage. Never stored, never accepted from a client, null when there are none.
    /// </summary>
    [NotMapped, JsonPropertyName("warnings")]
    public IReadOnlyList<string>? Warnings { get; set; }

    /// <summary>
    /// Whether a PQC private key is held server-side, for hybrid paired-issuance requests.
    /// </summary>
    [NotMapped]
    public bool HasPqcPrivateKey { get; set; }

    /// <summary>
    /// Base64url-encoded DER PKCS#10 CSR submitted by a CSR-based issuance path (ACME or EST) at finalize time.
    /// When set, the queue consumer signs the public key from this CSR rather than generating a new key pair.
    /// Null for manually created requests.
    /// </summary>
    public string? CsrPem { get; init; }

    /// <summary>
    /// Requested validity in days. Null takes the template's default, else the CA-wide default.
    /// A request may shorten its validity freely; exceeding the default it would otherwise get needs
    /// an issuance policy whose <c>MaxValidityDays</c> explicitly allows it.
    /// </summary>
    public int? ValidityDays { get; set; }

    /// <summary>
    /// The published <see cref="IssuancePolicyVersion"/> that most recently allowed this request, or
    /// null when the request is not governed by a policy. Written by the issuance pipeline only.
    /// </summary>
    public Guid? PolicyVersionId { get; set; }

    /// <summary>UTC timestamp of the evaluation that recorded <see cref="PolicyVersionId"/>.</summary>
    public DateTime? PolicyEvaluatedAtUtc { get; set; }

    /// <summary>
    /// The issuer that signed this certificate. Pipeline-only (written at issuance, never by
    /// create/update). Null on a row issued before issuers existed, which means the legacy issuer.
    /// </summary>
    public IssuerId? IssuerId { get; set; }

    /// <summary>Display name of <see cref="IssuerId"/>, filled by the API for detail responses. Not stored.</summary>
    [NotMapped]
    public string? IssuerName { get; set; }
}
