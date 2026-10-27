using System.ComponentModel.DataAnnotations;

namespace Qertum.Services;

/// <summary>Request body for creating a new certificate request.</summary>
public sealed class CreateCertificateRequestRequest
{
    /// <summary>X.509 Common Name (CN) for the certificate.</summary>
    [Required]
    [MaxLength(200)]
    public string CommonName { get; init; } = string.Empty;

    // Note: there is deliberately no RequestedBy here. The requester is taken from the caller's
    // token so it cannot be spoofed; a client that sends the field anyway has it ignored.

    /// <summary>Certificate type, e.g. "WebServer" or "Client".</summary>
    [Required]
    [MaxLength(50)]
    public string Type { get; init; } = "WebServer";

    /// <summary>JSON bag for type-specific properties such as SAN lists.</summary>
    [Required]
    public string PropertiesJson { get; init; } = "{}";

    // Note: there is deliberately no Status here either. Every request starts Pending and reaches
    // Approved only through /approve or a configured auto-approval path; a client that sends the
    // field anyway has it ignored.

    /// <summary>
    /// Requested validity in days, or null for the template's default. A request may shorten its
    /// validity freely; asking for more than that default needs an issuance policy that allows it.
    /// </summary>
    public int? ValidityDays { get; init; }

    /// <summary>Key algorithm for the issued certificate. Defaults to <see cref="CertificateKeyAlgorithm.Rsa"/> when omitted.</summary>
    public CertificateKeyAlgorithm? KeyAlgorithm { get; init; }

    /// <summary>Optional facts about the certificate (owner team, contact, purpose, target system, ticket, compatibility).</summary>
    public CertificateMetadata? Metadata { get; init; }
}

/// <summary>Request body for updating an existing certificate request.</summary>
public sealed class UpdateCertificateRequestRequest
{
    /// <summary>X.509 Common Name (CN) for the certificate.</summary>
    [Required]
    [MaxLength(200)]
    public string CommonName { get; set; } = string.Empty;

    // Note: there is deliberately no RequestedBy here. Updating a request must not reassign it to
    // another identity, so the stored requester is preserved untouched.

    /// <summary>Certificate type, e.g. "WebServer" or "Client".</summary>
    [Required]
    [MaxLength(50)]
    public string Type { get; set; } = "WebServer";

    /// <summary>JSON bag for type-specific properties such as SAN lists.</summary>
    [Required]
    public string PropertiesJson { get; set; } = "{}";

    /// <summary>Desired lifecycle status.</summary>
    public CertificateRequestStatus Status { get; set; }

    /// <summary>
    /// Requested validity in days, or null for the template's default. A request may shorten its
    /// validity freely; asking for more than that default needs an issuance policy that allows it.
    /// </summary>
    public int? ValidityDays { get; set; }

    /// <summary>Key algorithm for the issued certificate. Defaults to <see cref="CertificateKeyAlgorithm.Rsa"/> when omitted.</summary>
    public CertificateKeyAlgorithm? KeyAlgorithm { get; set; }
}

/// <summary>Request body for revoking a certificate.</summary>
/// <param name="Reason">Optional human-readable revocation reason.</param>
public sealed record RevokeRequest(string? Reason);

/// <summary>
/// Request body for exporting an issued certificate and its private key as PKCS#12.
/// Sent as a POST body rather than query parameters so the password never reaches an access log,
/// reverse-proxy log, or browser history.
/// </summary>
/// <param name="Password">Password protecting the resulting PKCS#12 file. May be empty.</param>
/// <param name="Pqc">Export the paired request's second certificate and key (the hybrid's PQC certificate, or a signing + encryption pair's encryption certificate) instead of the first.</param>
/// <param name="IncludeChain">Append the root CA certificate to the exported bundle.</param>
public sealed record ExportPfxRequest(string? Password, bool Pqc = false, bool IncludeChain = true);

/// <summary>Body of <c>POST /v1/issuers/{id}/pfx</c>.</summary>
/// <param name="Password">Password protecting the resulting PKCS#12 file. May be empty.</param>
/// <param name="IncludeChain">Append the CAs above the issuer, root included, to the exported bundle.</param>
public sealed record ExportIssuerPfxRequest(string? Password, bool IncludeChain = true);

/// <summary>Request body for setting the permissions of a role.</summary>
/// <param name="Permissions">List of permission constants to assign to the role.</param>
public sealed record SetRolePermissionsRequest(IReadOnlyList<string> Permissions);

/// <summary>Request body for generating a new root CA certificate during onboarding.</summary>
public sealed class GenerateCaRequest
{
    /// <summary>X.509 Common Name (CN) for the CA certificate.</summary>
    [Required]
    [MaxLength(200)]
    public string CommonName { get; set; } = string.Empty;

    /// <summary>
    /// Optional CA-wide PQC stage to apply before the root key is checked, so a classical root can be
    /// generated deliberately. Needs the admin role. Null keeps the current stage (default Enforce).
    /// </summary>
    public PqcStage? PqcStage { get; set; }

    /// <summary>Organization (O) in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? OrganizationName { get; set; }

    /// <summary>Organizational Unit (OU) in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? OrganizationalUnit { get; set; }

    /// <summary>Two-letter ISO country code (C) in the CA subject DN.</summary>
    [MaxLength(2)]
    public string? Country { get; set; }

    /// <summary>State or province (ST) in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? State { get; set; }

    /// <summary>Locality or city (L) in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? Locality { get; set; }

    /// <summary>
    /// Key algorithm for the CA certificate. Hybrid values are not valid for a CA key.
    /// Defaults to <see cref="CertificateKeyAlgorithm.Rsa"/> when omitted.
    /// </summary>
    public CertificateKeyAlgorithm? KeyAlgorithm { get; set; }

    /// <summary>CA certificate validity in days (1–36500). Defaults to 3650 (ten years).</summary>
    [Range(1, 36500)]
    public int ValidityDays { get; set; } = 3650;

    /// <summary>Required with <c>force=true</c>: exactly <c>REPLACE &lt;default issuer name&gt;</c>.</summary>
    public string? Confirm { get; set; }
}

/// <summary>Request body for importing an existing CA certificate and private key.</summary>
public sealed class ImportCaRequest
{
    /// <summary>PEM-encoded CA certificate (-----BEGIN CERTIFICATE-----).</summary>
    [Required]
    public string CertificatePem { get; set; } = string.Empty;

    /// <summary>PEM-encoded private key corresponding to the CA certificate.</summary>
    [Required]
    public string PrivateKeyPem { get; set; } = string.Empty;

    /// <summary>Required with <c>force=true</c>: exactly <c>REPLACE &lt;default issuer name&gt;</c>.</summary>
    public string? Confirm { get; set; }
}

/// <summary>Request body for creating or updating a certificate template.</summary>
public sealed class SaveCertificateTemplateRequest
{
    /// <summary>Human-readable display name for the template.</summary>
    [Required]
    [MaxLength(100)]
    public string Name { get; init; } = string.Empty;

    /// <summary>Machine key used as CertificateRequest.Type. Must be unique and immutable once set.</summary>
    [Required]
    [MaxLength(50)]
    public string TypeKey { get; init; } = string.Empty;

    /// <summary>Optional description of what this certificate type is used for.</summary>
    [MaxLength(500)]
    public string? Description { get; init; }

    /// <summary>JSON array of key-usage flag names.</summary>
    public string KeyUsagesJson { get; init; } = "[]";

    /// <summary>JSON array of Extended Key Usage OID strings.</summary>
    public string ExtendedKeyUsagesJson { get; init; } = "[]";

    /// <summary>JSON array of SAN type names: "dns", "ip", "email", "upn".</summary>
    public string SanTypesJson { get; init; } = "[]";

    /// <summary>JSON array of {Oid, Value, Critical} for custom X.509 v3 extensions.</summary>
    public string? CustomExtensionsJson { get; set; }

    /// <summary>Overrides global CertificateValidityDays when set. Null = use global setting.</summary>
    public int? ValidityDays { get; init; }
}

/// <summary>
/// Serialized into <see cref="CertificateRequest.PropertiesJson"/> for <see cref="WellKnownCertificateTypes.RootCa"/>
/// requests so the queue consumer can reconstruct the full <see cref="GenerateCaRequest"/>.
/// </summary>
public sealed class RootCaProperties
{
    /// <summary>Organization (O) for the CA subject DN.</summary>
    public string? OrganizationName { get; init; }

    /// <summary>Organizational Unit (OU) for the CA subject DN.</summary>
    public string? OrganizationalUnit { get; init; }

    /// <summary>Two-letter ISO country code (C) for the CA subject DN.</summary>
    public string? Country { get; init; }

    /// <summary>State or province (ST) for the CA subject DN.</summary>
    public string? State { get; init; }

    /// <summary>Locality or city (L) for the CA subject DN.</summary>
    public string? Locality { get; init; }

    /// <summary>CA certificate validity in days (1–36500). Defaults to 3650 (ten years).</summary>
    public int ValidityDays { get; init; } = 3650;

    /// <summary>
    /// The default issuer a force-generate replaces once this request is signed. Set only by
    /// <c>/ca/generate?force=true</c>, never taken from a client.
    /// </summary>
    public IssuerId? ReplaceIssuerId { get; init; }

    /// <summary>
    /// True when this root is the first one after every default issuer was taken out of service by a revoked
    /// certificate. It is created in its own issuer directory and registered as the new default; the revoked
    /// issuers are left as they are so they keep answering CRL and OCSP. Set only by <c>/ca/generate</c>.
    /// </summary>
    public bool AfterRevokedIssuer { get; init; }
}

/// <summary>Request body for creating or updating a webhook subscription.</summary>
public sealed class SaveWebhookRequest
{
    /// <summary>Human-readable display name.</summary>
    [Required]
    [MaxLength(200)]
    public string Name { get; init; } = string.Empty;

    /// <summary>Target URL that receives HTTP POST deliveries.</summary>
    [Required]
    [MaxLength(2000)]
    [Url]
    public string Url { get; init; } = string.Empty;

    /// <summary>
    /// The event family this webhook receives. Absent means <see cref="WebhookEventFamily.CertificateRequest"/>,
    /// so a client written before families shipped keeps its behaviour.
    /// </summary>
    public WebhookEventFamily Family { get; init; } = WebhookEventFamily.CertificateRequest;

    /// <summary>
    /// Optional HMAC-SHA256 signing secret. On update: <see langword="null"/> leaves the existing
    /// secret unchanged; empty string clears it.
    /// </summary>
    public string? Secret { get; set; }

    /// <summary>
    /// JSON array naming the subset of <see cref="Family"/> to deliver (e.g. <c>["Issued","Revoked"]</c>).
    /// An empty array means every event in the family.
    /// </summary>
    public string EventsJson { get; init; } = "[]";

    /// <summary>When <see langword="false"/>, no deliveries are attempted for this webhook.</summary>
    public bool IsEnabled { get; init; } = true;
}

/// <summary>An ACME external account credential, without its MAC key.</summary>
/// <param name="Id">Identifier of the credential.</param>
/// <param name="Kid">Key id the client sends in its binding JWS.</param>
/// <param name="Description">Operator-facing label.</param>
/// <param name="IsEnabled">Whether the credential may still be used.</param>
/// <param name="BoundAccountId">The ACME account it registered, once used.</param>
/// <param name="CreatedAtUtc">When it was issued.</param>
/// <param name="BoundAtUtc">When it was used to register an account.</param>
public sealed record AcmeExternalAccountKeyResponse(
    Guid Id,
    string Kid,
    string Description,
    bool IsEnabled,
    Guid? BoundAccountId,
    DateTime CreatedAtUtc,
    DateTime? BoundAtUtc);

/// <summary>
/// A newly issued credential, including the MAC key. This is the only response that carries the key —
/// it is not retrievable afterwards, so it must be handed to its holder now.
/// </summary>
/// <param name="Credential">The credential's stored fields.</param>
/// <param name="MacKey">Base64url-encoded HMAC key, shown once.</param>
public sealed record AcmeExternalAccountKeyCreatedResponse(
    AcmeExternalAccountKeyResponse Credential,
    string MacKey);

/// <summary>Request to issue an ACME external account credential.</summary>
/// <param name="Description">Operator-facing label, e.g. the team the credential is for.</param>
public sealed record CreateAcmeExternalAccountKeyRequest(string? Description);

/// <summary>Request to enable or disable an ACME external account credential.</summary>
/// <param name="IsEnabled">Whether the credential may be used.</param>
public sealed record UpdateAcmeExternalAccountKeyRequest(bool IsEnabled);

/// <summary>An EST enrollment credential, without its password.</summary>
public sealed record EstEnrollmentCredentialResponse(
    Guid Id, string Username, string Description, bool IsEnabled, DateTime CreatedAtUtc);

/// <summary>
/// A newly issued credential, including the plaintext password. This is the only response that
/// carries it — it is not retrievable afterwards, so it must be handed to its holder now.
/// </summary>
public sealed record EstEnrollmentCredentialCreatedResponse(
    EstEnrollmentCredentialResponse Credential, string Password);

/// <summary>Request to issue an EST enrollment credential.</summary>
public sealed record CreateEstEnrollmentCredentialRequest(string Username, string Password, string? Description);

/// <summary>Request to enable or disable an EST enrollment credential.</summary>
public sealed record UpdateEstEnrollmentCredentialRequest(bool IsEnabled);

/// <summary>Current secret storage provider and whether a TPM is available to upgrade to.</summary>
public sealed record SecretStorageStatusResponse(string CurrentProvider, bool TpmAvailable);

/// <summary>Requests a migration of at-rest secrets to a different <c>SecretStorageProvider</c>.</summary>
public sealed record MigrateSecretStorageRequest(string TargetProvider);

/// <summary>
/// The new delta CRL base published by a forced reset (<c>POST /v1/crl/reset-base</c>) — the same
/// full-CRL number and timestamp a <c>GET /crl</c> would have recorded, just published on demand.
/// </summary>
public sealed record CrlBaseResetResponse(long CrlNumber, DateTime ThisUpdateUtc);

/// <summary>Request body linking a certificate template to an issuance policy, or unlinking it with null.</summary>
public sealed class SetTemplateIssuancePolicyRequest
{
    /// <summary>The policy to enforce for the template; null removes the link.</summary>
    public IssuancePolicyId? IssuancePolicyId { get; init; }
}

/// <summary>Body of <c>PUT /v1/settings/ca-approval</c> (admin only).</summary>
public sealed class SetCaApprovalRequest
{
    /// <summary>True: approver must differ from requester. False: waived. Required.</summary>
    public bool? RequireIndependentApproval { get; init; }
}

/// <summary>Body of <c>PUT /v1/settings/issuer-strength</c> (admin only).</summary>
public sealed class SetIssuerStrengthRequest
{
    /// <summary><c>Off</c>, <c>Warn</c> or <c>Enforce</c>. Required.</summary>
    public IssuerStrengthMode? Mode { get; init; }
}

/// <summary>Body of <c>PUT /v1/settings/revoked-issuer</c> (admin only).</summary>
public sealed class SetRevokedIssuerModeRequest
{
    /// <summary><c>HardStop</c> or <c>Retire</c>. Required.</summary>
    public RevokedIssuerMode? Mode { get; init; }
}

/// <summary>Body of <c>PUT /v1/settings/two-person-approval</c> (admin only).</summary>
public sealed class SetTwoPersonApprovalRequest
{
    /// <summary>True: the sensitive operations need a second administrator's approval. False: they do not. Required.</summary>
    public bool? Enabled { get; init; }
}

/// <summary>Body of <c>PUT /v1/settings/pqc-stage</c>. <see cref="Stage"/> is required.</summary>
public sealed class SetPqcStageRequest
{
    /// <summary>The new CA default stage.</summary>
    public PqcStage? Stage { get; init; }
}

/// <summary>Body of <c>PUT /v1/certificate-templates/{id}/pqc-stage</c>. Null clears the override.</summary>
public sealed class SetTemplatePqcStageRequest
{
    /// <summary>The template's stage, or null to follow the CA default.</summary>
    public PqcStage? Stage { get; init; }
}

/// <summary>Body of <c>PUT /v1/certificate-templates/{id}/issuer</c>.</summary>
public sealed class SetTemplateIssuerRequest
{
    /// <summary>The issuer that signs the template's certificates; null = the default issuer.</summary>
    public IssuerId? IssuerId { get; set; }
}
