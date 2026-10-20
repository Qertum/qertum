namespace Qertum.Services;

/// <summary>
/// Event type strings recognised by the webhook delivery system, grouped into families. The names
/// are the audit action strings the services already write — keep the two in step when adding one.
/// </summary>
public static class WellKnownWebhookEvents
{
    // Certificate request lifecycle.
    /// <summary>The <c>Created</c> event (audit action of the same name).</summary>
    public const string Created = "Created";
    /// <summary>The <c>Approved</c> event (audit action of the same name).</summary>
    public const string Approved = "Approved";
    /// <summary>The <c>Rejected</c> event (audit action of the same name).</summary>
    public const string Rejected = "Rejected";
    /// <summary>The <c>Issued</c> event (audit action of the same name).</summary>
    public const string Issued = "Issued";
    /// <summary>The <c>Revoked</c> event (audit action of the same name).</summary>
    public const string Revoked = "Revoked";
    /// <summary>The <c>Renewed</c> event (audit action of the same name).</summary>
    public const string Renewed = "Renewed";
    /// <summary>The <c>Updated</c> event (audit action of the same name).</summary>
    public const string Updated = "Updated";
    /// <summary>The <c>Deleted</c> event (audit action of the same name).</summary>
    public const string Deleted = "Deleted";

    // Settings.
    /// <summary>The <c>SettingsUpdated</c> event (audit action of the same name).</summary>
    public const string SettingsUpdated = "SettingsUpdated";
    /// <summary>The <c>RolePermissionsUpdated</c> event (audit action of the same name).</summary>
    public const string RolePermissionsUpdated = "RolePermissionsUpdated";
    /// <summary>The <c>RolePermissionsRenamed</c> event (audit action of the same name).</summary>
    public const string RolePermissionsRenamed = "RolePermissionsRenamed";

    /// <summary>The <c>PqcStageChanged</c> event (audit action of the same name).</summary>
    public const string PqcStageChanged = "PqcStageChanged";
    /// <summary>The <c>CaApprovalRuleChanged</c> event (audit action of the same name).</summary>
    public const string CaApprovalRuleChanged = "CaApprovalRuleChanged";
    /// <summary>The <c>PqcExceptionCreated</c> event (audit action of the same name).</summary>
    public const string PqcExceptionCreated = "PqcExceptionCreated";
    /// <summary>The <c>PqcExceptionRevoked</c> event (audit action of the same name).</summary>
    public const string PqcExceptionRevoked = "PqcExceptionRevoked";

    // Certificate templates.
    /// <summary>The <c>TemplateCreated</c> event (audit action of the same name).</summary>
    public const string TemplateCreated = "TemplateCreated";
    /// <summary>The <c>TemplateUpdated</c> event (audit action of the same name).</summary>
    public const string TemplateUpdated = "TemplateUpdated";
    /// <summary>The <c>TemplateDeleted</c> event (audit action of the same name).</summary>
    public const string TemplateDeleted = "TemplateDeleted";
    /// <summary>The <c>TemplatePolicyChanged</c> event (audit action of the same name).</summary>
    public const string TemplatePolicyChanged = "TemplatePolicyChanged";
    /// <summary>The <c>TemplateIssuerChanged</c> event (audit action of the same name).</summary>
    public const string TemplateIssuerChanged = "TemplateIssuerChanged";
    /// <summary>The <c>TemplatePqcStageChanged</c> event (audit action of the same name).</summary>
    public const string TemplatePqcStageChanged = "TemplatePqcStageChanged";

    // Two-person approval.
    /// <summary>The <c>ApprovalRequested</c> event (audit action of the same name).</summary>
    public const string ApprovalRequested = "ApprovalRequested";
    /// <summary>The <c>ApprovalApproved</c> event (audit action of the same name).</summary>
    public const string ApprovalApproved = "ApprovalApproved";
    /// <summary>The <c>ApprovalDenied</c> event (audit action of the same name).</summary>
    public const string ApprovalDenied = "ApprovalDenied";
    /// <summary>The <c>ApprovalUsed</c> event (audit action of the same name).</summary>
    public const string ApprovalUsed = "ApprovalUsed";
    /// <summary>The <c>ApprovalExpired</c> event (audit action of the same name): a request or an approved grant ran out of time.</summary>
    public const string ApprovalExpired = "ApprovalExpired";
    /// <summary>The <c>TwoPersonApprovalChanged</c> event: the two-person approval switch was turned on or off.</summary>
    public const string TwoPersonApprovalChanged = "TwoPersonApprovalChanged";

    // Bulk operations.
    /// <summary>The <c>BulkOperationCompleted</c> event (audit action of the same name).</summary>
    public const string BulkOperationCompleted = "BulkOperationCompleted";

    // Issuers.
    /// <summary>The <c>IssuerRegistered</c> event (audit action of the same name).</summary>
    public const string IssuerRegistered = "IssuerRegistered";
    /// <summary>The <c>IssuerCreated</c> event (audit action of the same name).</summary>
    public const string IssuerCreated = "IssuerCreated";
    /// <summary>The <c>IssuerCertificateInstalled</c> event (audit action of the same name).</summary>
    public const string IssuerCertificateInstalled = "IssuerCertificateInstalled";
    /// <summary>The <c>IssuerCrlUploaded</c> event (audit action of the same name).</summary>
    public const string IssuerCrlUploaded = "IssuerCrlUploaded";
    /// <summary>The <c>IssuerMadeDefault</c> event (audit action of the same name).</summary>
    public const string IssuerMadeDefault = "IssuerMadeDefault";
    /// <summary>The <c>IssuerRetired</c> event (audit action of the same name).</summary>
    public const string IssuerRetired = "IssuerRetired";
    /// <summary>The <c>IssuerArchived</c> event (audit action of the same name).</summary>
    public const string IssuerArchived = "IssuerArchived";
    /// <summary>The <c>IssuerDeleted</c> event (audit action of the same name).</summary>
    public const string IssuerDeleted = "IssuerDeleted";
    /// <summary>The <c>IssuerDestroyed</c> event (audit action of the same name).</summary>
    public const string IssuerDestroyed = "IssuerDestroyed";

    // Issuance policies.
    /// <summary>The <c>IssuancePolicyCreated</c> event (audit action of the same name).</summary>
    public const string IssuancePolicyCreated = "IssuancePolicyCreated";
    /// <summary>The <c>IssuancePolicyUpdated</c> event (audit action of the same name).</summary>
    public const string IssuancePolicyUpdated = "IssuancePolicyUpdated";
    /// <summary>The <c>IssuancePolicyDeleted</c> event (audit action of the same name).</summary>
    public const string IssuancePolicyDeleted = "IssuancePolicyDeleted";
    /// <summary>The <c>IssuancePolicyDraftSaved</c> event (audit action of the same name).</summary>
    public const string IssuancePolicyDraftSaved = "IssuancePolicyDraftSaved";
    /// <summary>The <c>IssuancePolicyDraftDiscarded</c> event (audit action of the same name).</summary>
    public const string IssuancePolicyDraftDiscarded = "IssuancePolicyDraftDiscarded";
    /// <summary>The <c>IssuancePolicyPublished</c> event (audit action of the same name).</summary>
    public const string IssuancePolicyPublished = "IssuancePolicyPublished";

    // Key egress.
    /// <summary>The <c>PrivateKeyDownloaded</c> event (audit action of the same name).</summary>
    public const string PrivateKeyDownloaded = "PrivateKeyDownloaded";
    /// <summary>The <c>PfxExported</c> event (audit action of the same name).</summary>
    public const string PfxExported = "PfxExported";
    /// <summary>The <c>IssuerKeyDownloaded</c> event (audit action of the same name): a CA issuer's private key left the server.</summary>
    public const string IssuerKeyDownloaded = "IssuerKeyDownloaded";
    /// <summary>The <c>IssuerPfxExported</c> event (audit action of the same name): a CA issuer's key left the server as PKCS#12.</summary>
    public const string IssuerPfxExported = "IssuerPfxExported";

    /// <summary>A certificate is within a configured day threshold of its expiry and has no renewal.</summary>
    public const string CertificateExpiring = "CertificateExpiring";

    /// <summary>A renewal has been waiting for approval longer than the attention age.</summary>
    public const string RenewalStalled = "RenewalStalled";

    /// <summary>A renewal was rejected by the pipeline.</summary>
    public const string RenewalFailed = "RenewalFailed";

    /// <summary>The head of every audit hash chain, sent periodically as an off-host anchor.</summary>
    public const string AuditCheckpoint = "AuditCheckpoint";

    private static readonly Dictionary<WebhookEventFamily, IReadOnlySet<string>> ByFamily = new()
    {
        [WebhookEventFamily.CertificateRequest] = new HashSet<string>(StringComparer.Ordinal)
        {
            Created, Approved, Rejected, Issued, Revoked, Renewed, Updated, Deleted
        },
        [WebhookEventFamily.Settings] = new HashSet<string>(StringComparer.Ordinal)
        {
            SettingsUpdated, RolePermissionsUpdated, RolePermissionsRenamed, PqcStageChanged,
            PqcExceptionCreated, PqcExceptionRevoked, CaApprovalRuleChanged, TwoPersonApprovalChanged
        },
        [WebhookEventFamily.Template] = new HashSet<string>(StringComparer.Ordinal)
        {
            TemplateCreated, TemplateUpdated, TemplateDeleted, TemplatePolicyChanged, TemplateIssuerChanged, TemplatePqcStageChanged
        },
        [WebhookEventFamily.Policy] = new HashSet<string>(StringComparer.Ordinal)
        {
            IssuancePolicyCreated, IssuancePolicyUpdated, IssuancePolicyDeleted,
            IssuancePolicyDraftSaved, IssuancePolicyDraftDiscarded, IssuancePolicyPublished
        },
        [WebhookEventFamily.KeyAccess] = new HashSet<string>(StringComparer.Ordinal)
        {
            PrivateKeyDownloaded, PfxExported, IssuerKeyDownloaded, IssuerPfxExported
        },
        [WebhookEventFamily.Issuer] = new HashSet<string>(StringComparer.Ordinal)
        {
            IssuerRegistered, IssuerCreated, IssuerCertificateInstalled, IssuerCrlUploaded, IssuerMadeDefault, IssuerRetired, IssuerArchived, IssuerDeleted, IssuerDestroyed
        },
        [WebhookEventFamily.BulkOperation] = new HashSet<string>(StringComparer.Ordinal)
        {
            BulkOperationCompleted
        },
        [WebhookEventFamily.Notice] = new HashSet<string>(StringComparer.Ordinal)
        {
            CertificateExpiring, RenewalStalled, RenewalFailed
        },
        [WebhookEventFamily.Audit] = new HashSet<string>(StringComparer.Ordinal)
        {
            AuditCheckpoint
        },
        [WebhookEventFamily.Approval] = new HashSet<string>(StringComparer.Ordinal)
        {
            ApprovalRequested, ApprovalApproved, ApprovalDenied, ApprovalUsed, ApprovalExpired
        }
    };

    private static readonly Dictionary<string, WebhookEventFamily> FamilyByEvent =
        ByFamily.SelectMany(pair => pair.Value.Select(e => (Event: e, Family: pair.Key)))
                .ToDictionary(x => x.Event, x => x.Family, StringComparer.OrdinalIgnoreCase);

    /// <summary>All valid event type strings: the union of every family.</summary>
    public static readonly IReadOnlySet<string> All =
        ByFamily.Values.SelectMany(v => v).ToHashSet(StringComparer.Ordinal);

    /// <summary>The events belonging to <paramref name="family"/>.</summary>
    public static IReadOnlySet<string> EventsFor(WebhookEventFamily family) => ByFamily[family];

    /// <summary>The family owning <paramref name="eventName"/>, matched case-insensitively.</summary>
    public static WebhookEventFamily FamilyOf(string eventName) =>
        TryGetFamily(eventName, out var family)
            ? family
            : throw new ArgumentOutOfRangeException(nameof(eventName), eventName, "Unknown webhook event type.");

    /// <summary>Non-throwing form of <see cref="FamilyOf"/>.</summary>
    public static bool TryGetFamily(string eventName, out WebhookEventFamily family) =>
        FamilyByEvent.TryGetValue(eventName, out family);
}
