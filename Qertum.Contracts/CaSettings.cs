using System.ComponentModel.DataAnnotations;

namespace Qertum.Services;

/// <summary>CA-wide configuration stored as a singleton row (Id = 1).</summary>
public sealed class CaSettings
{
    /// <summary>Singleton row identifier; always 1.</summary>
    public int Id { get; set; } = 1;

    /// <summary>Organization name (O) embedded in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? OrganizationName { get; set; }

    /// <summary>Organizational unit (OU) embedded in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? OrganizationalUnit { get; set; }

    /// <summary>Two-letter ISO country code (C) embedded in the CA subject DN.</summary>
    [MaxLength(2)]
    public string? Country { get; set; }

    /// <summary>State or province (ST) embedded in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? State { get; set; }

    /// <summary>Locality (L) embedded in the CA subject DN.</summary>
    [MaxLength(200)]
    public string? Locality { get; set; }

    /// <summary>
    /// Full URL for the CRL distribution point, e.g. https://ca.example.com/crl.
    /// If set, it is embedded in issued certificates as a CDP extension.
    /// </summary>
    [MaxLength(2000)]
    [Url]
    public string? CrlDistributionPoint { get; set; }

    /// <summary>
    /// Full URL of the OCSP responder, e.g. https://ca.example.com/ocsp.
    /// If set, it is embedded in issued certificates as an Authority Information Access extension,
    /// which is what makes a relying party check status there instead of downloading the whole CRL.
    /// </summary>
    [MaxLength(2000)]
    [Url]
    public string? OcspResponderUrl { get; set; }

    /// <summary>
    /// Public base URL of the API (e.g. <c>https://ca.example.com</c>). When set, certificates signed
    /// by non-legacy issuers carry an AIA caIssuers URL pointing at
    /// <c>{PublicBaseUrl}/v1/issuers/{id}/certificate</c>. Unset = no caIssuers extension.
    /// </summary>
    [Url]
    public string? PublicBaseUrl { get; set; }

    /// <summary>
    /// When true, <c>POST /acme/new-account</c> requires a valid external account binding
    /// (RFC 8555 §7.3.4), so only holders of a pre-issued key id and MAC key can register.
    /// Leave false only where every client that can reach the ACME endpoint is already trusted.
    /// </summary>
    public bool AcmeRequireExternalAccountBinding { get; set; }

    /// <summary>
    /// Number of days before expiration to consider a certificate "expiring soon".
    /// </summary>
    public int ExpiringSoonDays { get; set; } = 30;

    /// <summary>
    /// Validity period in days for newly issued leaf certificates. Defaults to 365.
    /// </summary>
    public int CertificateValidityDays { get; set; } = 365;

    /// <summary>
    /// Validity window in hours for newly generated CRLs. Defaults to 24.
    /// </summary>
    public int CrlValidityHours { get; set; } = 24;

    /// <summary>
    /// When <see langword="true"/>, the source certificate is automatically revoked with reason "superseded"
    /// when a renewal request is created for it. When <see langword="false"/> (default), the source certificate
    /// remains valid until it expires or is manually revoked, allowing an overlap period during deployment.
    /// </summary>
    public bool AutoRevokeOnRenewal { get; set; }

    /// <summary>
    /// When <see langword="true"/>, ACME orders are automatically approved once every identifier is validated
    /// (by http-01 or dns-01),
    /// bypassing the manual approval queue. When <see langword="false"/> (default), ACME orders land in the
    /// normal Pending queue and require a human to approve them before the certificate is issued.
    /// </summary>
    public bool AcmeAutoApprove { get; set; }

    /// <summary>
    /// When <see langword="true"/>, EST enrollments (<c>/simpleenroll</c>, <c>/simplereenroll</c>) are
    /// automatically approved on submission, bypassing the manual approval queue. When
    /// <see langword="false"/> (default), they land in the normal Pending queue. Independently
    /// toggleable from <see cref="AcmeAutoApprove"/> — a deployment can auto-approve one protocol
    /// and not the other.
    /// </summary>
    public bool EstAutoApprove { get; set; }

    /// <summary>
    /// When <see langword="true"/>, the scheduler automatically creates renewal requests for issued certificates
    /// approaching expiry. When <see langword="false"/> (default), renewal is manual.
    /// </summary>
    public bool AutoRenewalEnabled { get; set; }

    /// <summary>
    /// Number of days before expiry at which the auto-renewal scheduler triggers.
    /// When <see langword="null"/>, uses <see cref="ExpiringSoonDays"/> as the threshold.
    /// </summary>
    public int? AutoRenewalDaysBeforeExpiry { get; set; }

    /// <summary>
    /// When <see langword="true"/>, renewal requests created by the auto-renewal scheduler are immediately
    /// approved and queued for issuance. When <see langword="false"/> (default), they land in the Pending
    /// queue for manual admin approval.
    /// </summary>
    public bool AutoRenewalAutoApprove { get; set; }

    /// <summary>
    /// When <see langword="true"/>, the sensitive operations in the two-person approval table (key export by a
    /// non-owner, issuer changes, bulk revoke, policy publish) need an approval from a second administrator.
    /// Off by default. Changed only through <c>PUT /v1/settings/two-person-approval</c> (admin role); a general
    /// settings save carries the stored value.
    /// </summary>
    public bool RequireTwoPersonApproval { get; set; }

    /// <summary>
    /// When true (the default) a request for a CA-capable template (<c>KeyCertSign</c>) must be approved
    /// by someone other than its requester, admin included. Changed only through
    /// <c>PUT /v1/settings/ca-approval</c> (admin role); a general settings save carries the stored value.
    /// </summary>
    public bool RequireIndependentCaApproval { get; set; } = true;

    /// <summary>
    /// JSON array of CIDR ranges an ACME http-01 challenge is permitted to reach, e.g.
    /// <c>["10.1.0.0/16","192.168.4.0/24"]</c>. The list is <b>exclusive</b>: an address is reachable only
    /// if it matches an entry, so an empty or absent list blocks every http-01 challenge. Link-local addresses
    /// are rejected even when an entry covers them. dns-01 is not governed by this list: it queries only the
    /// resolvers in <c>Acme:Dns01:Resolvers</c>.
    /// </summary>
    [MaxLength(4000)]
    public string? AcmeChallengeAllowedNetworksJson { get; set; }

    /// <summary>
    /// Highest CRL number published so far (RFC 5280 §5.2.3). Claimed and incremented atomically each
    /// time a CRL is generated, so concurrent API instances cannot publish two different CRLs under
    /// the same number. Not operator-editable.
    /// </summary>
    public long CrlNumber { get; set; }

    /// <summary>
    /// When <see langword="true"/>, <c>/crl</c> and <c>/v1/crl</c> record the CRL number and
    /// timestamp of each full CRL they publish, and <c>/crl/delta</c> becomes available to serve
    /// only the revocations since that base. When <see langword="false"/> (default), the delta
    /// endpoint always answers 404 and the base fields below are not written.
    /// </summary>
    public bool DeltaCrlEnabled { get; set; }

    /// <summary>
    /// Full URL where the delta CRL is published, e.g. https://ca.example.com/crl/delta. When set
    /// (and <see cref="DeltaCrlEnabled"/> is true), it is embedded in the full CRL as a Freshest CRL
    /// extension (RFC 5280 §5.2.6), which is what tells a delta-aware client where to look.
    /// </summary>
    [MaxLength(2000)]
    [Url]
    public string? CrlDeltaDistributionPoint { get; set; }

    /// <summary>
    /// Validity window in hours for a generated delta CRL. Defaults to 6 — shorter than
    /// <see cref="CrlValidityHours"/> because a delta is meant to be cheap to refresh often.
    /// </summary>
    public int DeltaCrlValidityHours { get; set; } = 6;

    /// <summary>
    /// CRL number of the most recently published full CRL (RFC 5280 §5.2.3). A delta CRL is only
    /// meaningful relative to a base, so this is <see langword="null"/> until the first full CRL is
    /// generated. Not operator-editable — written by the full-CRL endpoint alongside <see cref="CrlNumber"/>.
    /// </summary>
    public long? BaseCrlNumber { get; set; }

    /// <summary>
    /// <c>thisUpdate</c> timestamp (UTC) of the most recently published full CRL. The delta CRL
    /// includes exactly the certificates revoked after this instant. Not operator-editable.
    /// </summary>
    public DateTime? BaseCrlThisUpdateUtc { get; set; }

    /// <summary>
    /// Age, in hours, after which a <c>Pending</c> request is reported on the dashboard's attention
    /// view as waiting too long for approval. Defaults to 72.
    /// </summary>
    public int AttentionPendingApprovalAgeHours { get; set; } = 72;

    /// <summary>
    /// How many days back the dashboard's attention view looks for failed issuance and failed
    /// webhook deliveries. A failure older than this leaves the view. Defaults to 7.
    /// </summary>
    public int AttentionFailureLookbackDays { get; set; } = 7;

    /// <summary>
    /// Age, in hours, after which the last backup reported by the backup script is flagged on the
    /// dashboard's attention view. Defaults to 48.
    /// </summary>
    public int AttentionBackupMaxAgeHours { get; set; } = 48;

    /// <summary>
    /// Age, in days, after which the last verified restore reported by the restore test is flagged on
    /// the dashboard's attention view. Only a record of kind <c>verified</c> is judged. Defaults to 35.
    /// </summary>
    public int AttentionRestoreVerifiedMaxAgeDays { get; set; } = 35;

    /// <summary>
    /// <c>TypeKey</c> of the certificate template — and therefore the issuance policy — every ACME
    /// order is filed under. Defaults to <c>"WebServer"</c>. Changing it changes what policy governs
    /// ACME issuance, so the settings save requires <c>policies.publish</c>.
    /// </summary>
    [MaxLength(50)]
    public string AcmeTemplateTypeKey { get; set; } = "WebServer";

    /// <summary>
    /// <c>TypeKey</c> of the certificate template — and therefore the issuance policy — every EST
    /// enrollment is filed under. Defaults to <c>"WebServer"</c>. Changing it changes what policy
    /// governs EST issuance, so the settings save requires <c>policies.publish</c>.
    /// </summary>
    [MaxLength(50)]
    public string EstTemplateTypeKey { get; set; } = "WebServer";

    /// <summary>
    /// The CA-wide default PQC stage, used by templates without an override and by CA generate/import.
    /// Defaults to <see cref="PqcStage.Enforce"/>: a fresh CA refuses classical keys until an admin
    /// chooses otherwise. Changed only through <c>PUT /v1/settings/pqc-stage</c>; a general settings
    /// save carries the stored value across.
    /// </summary>
    public PqcStage PqcStage { get; set; } = PqcStage.Enforce;

    /// <summary>
    /// What happens when a certificate's post-quantum key claims a higher NIST level than the CA key that
    /// signs it. Defaults to <see cref="IssuerStrengthMode.Warn"/>. A classical issuer is exempt. Changed only
    /// through <c>PUT /v1/settings/issuer-strength</c> (admin role); a general settings save carries the stored value.
    /// </summary>
    public IssuerStrengthMode IssuerStrengthMode { get; set; } = IssuerStrengthMode.Warn;
}
