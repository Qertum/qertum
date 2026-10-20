namespace Qertum.Services.Lifecycle;

/// <summary>
/// Which kind of resource an audit action's <c>ResourceId</c> names. Audit entries do not record it,
/// and templates, policies, EAB keys and EST credentials pass their own ids alongside certificate
/// requests. <c>AuditActionSubjectsTests</c> scans every <c>LogAsync</c> call site, so an action added
/// without an entry here fails the build's tests rather than vanishing from every timeline.
/// </summary>
public static class AuditActionSubjects
{
    private static readonly Dictionary<string, string> Subjects = new(StringComparer.Ordinal)
    {
        ["Created"] = LifecycleSubjectTypes.CertificateRequest,
        ["Approved"] = LifecycleSubjectTypes.CertificateRequest,
        ["Rejected"] = LifecycleSubjectTypes.CertificateRequest,
        ["Issued"] = LifecycleSubjectTypes.CertificateRequest,
        ["Revoked"] = LifecycleSubjectTypes.CertificateRequest,
        ["Renewed"] = LifecycleSubjectTypes.CertificateRequest,
        ["Updated"] = LifecycleSubjectTypes.CertificateRequest,
        ["Deleted"] = LifecycleSubjectTypes.CertificateRequest,
        ["PolicyRejected"] = LifecycleSubjectTypes.CertificateRequest,
        ["ApprovalBlockedByPolicy"] = LifecycleSubjectTypes.CertificateRequest,
        ["ApprovalPreviewed"] = LifecycleSubjectTypes.CertificateRequest,
        ["IssuanceQueued"] = LifecycleSubjectTypes.CertificateRequest,
        ["RevocationQueued"] = LifecycleSubjectTypes.CertificateRequest,
        ["PrivateKeyDownloaded"] = LifecycleSubjectTypes.CertificateRequest,
        ["CertificateMetadataUpdated"] = LifecycleSubjectTypes.CertificateRequest,
        ["NoticeRaised"] = LifecycleSubjectTypes.CertificateRequest,
        ["NoteAdded"] = LifecycleSubjectTypes.CertificateRequest,
        ["NoteEdited"] = LifecycleSubjectTypes.CertificateRequest,
        ["NoteDeleted"] = LifecycleSubjectTypes.CertificateRequest,
        ["PfxExported"] = LifecycleSubjectTypes.CertificateRequest,

        ["TemplateCreated"] = LifecycleSubjectTypes.CertificateTemplate,
        ["TemplateUpdated"] = LifecycleSubjectTypes.CertificateTemplate,
        ["TemplateDeleted"] = LifecycleSubjectTypes.CertificateTemplate,
        ["TemplatePolicyChanged"] = LifecycleSubjectTypes.CertificateTemplate,

        ["IssuancePolicyCreated"] = LifecycleSubjectTypes.IssuancePolicy,
        ["IssuancePolicyUpdated"] = LifecycleSubjectTypes.IssuancePolicy,
        ["IssuancePolicyDraftSaved"] = LifecycleSubjectTypes.IssuancePolicy,
        ["IssuancePolicyDraftDiscarded"] = LifecycleSubjectTypes.IssuancePolicy,
        ["IssuancePolicyPublished"] = LifecycleSubjectTypes.IssuancePolicy,
        ["IssuancePolicyDeleted"] = LifecycleSubjectTypes.IssuancePolicy,
        ["IssuancePolicyArchived"] = LifecycleSubjectTypes.IssuancePolicy,
        ["IssuancePolicyUnarchived"] = LifecycleSubjectTypes.IssuancePolicy,

        ["AcmeExternalAccountKeyCreated"] = LifecycleSubjectTypes.AcmeExternalAccountKey,
        ["AcmeExternalAccountKeyEnabled"] = LifecycleSubjectTypes.AcmeExternalAccountKey,
        ["AcmeExternalAccountKeyDisabled"] = LifecycleSubjectTypes.AcmeExternalAccountKey,
        ["AcmeExternalAccountKeyDeleted"] = LifecycleSubjectTypes.AcmeExternalAccountKey,

        ["EstEnrollmentCredentialCreated"] = LifecycleSubjectTypes.EstCredential,
        ["EstEnrollmentCredentialEnabled"] = LifecycleSubjectTypes.EstCredential,
        ["EstEnrollmentCredentialDisabled"] = LifecycleSubjectTypes.EstCredential,
        ["EstEnrollmentCredentialDeleted"] = LifecycleSubjectTypes.EstCredential,

        ["WebhookDestinationRuleAdded"] = LifecycleSubjectTypes.WebhookDestinationRule,
        ["WebhookDestinationRuleToggled"] = LifecycleSubjectTypes.WebhookDestinationRule,
        ["WebhookDestinationRuleDeleted"] = LifecycleSubjectTypes.WebhookDestinationRule,

        ["IssuerRegistered"] = LifecycleSubjectTypes.Issuer,
        ["IssuerCreated"] = LifecycleSubjectTypes.Issuer,
        ["IssuerCertificateInstalled"] = LifecycleSubjectTypes.Issuer,
        ["IssuerCrlUploaded"] = LifecycleSubjectTypes.Issuer,
        ["IssuerMadeDefault"] = LifecycleSubjectTypes.Issuer,
        ["IssuerRetired"] = LifecycleSubjectTypes.Issuer,
        ["IssuerArchived"] = LifecycleSubjectTypes.Issuer,
        ["IssuerDeleted"] = LifecycleSubjectTypes.Issuer,
        ["IssuerDestroyed"] = LifecycleSubjectTypes.Issuer,
        ["IssuerKeyDownloaded"] = LifecycleSubjectTypes.Issuer,
        ["IssuerPfxExported"] = LifecycleSubjectTypes.Issuer,
        ["TemplateIssuerChanged"] = LifecycleSubjectTypes.CertificateTemplate,
        ["TemplatePqcStageChanged"] = LifecycleSubjectTypes.CertificateTemplate,
        [WellKnownWebhookEvents.PqcExceptionCreated] = LifecycleSubjectTypes.PqcException,
        [WellKnownWebhookEvents.PqcExceptionRevoked] = LifecycleSubjectTypes.PqcException,

        ["BulkOperationPreviewed"] = LifecycleSubjectTypes.BulkOperation,
        ["BulkOperationStarted"] = LifecycleSubjectTypes.BulkOperation,
        [WellKnownWebhookEvents.BulkOperationCompleted] = LifecycleSubjectTypes.BulkOperation,
        ["BulkOperationCancelled"] = LifecycleSubjectTypes.BulkOperation,

        [WellKnownWebhookEvents.ApprovalRequested] = LifecycleSubjectTypes.Approval,
        [WellKnownWebhookEvents.ApprovalApproved] = LifecycleSubjectTypes.Approval,
        [WellKnownWebhookEvents.ApprovalDenied] = LifecycleSubjectTypes.Approval,
        [WellKnownWebhookEvents.ApprovalUsed] = LifecycleSubjectTypes.Approval,
        [WellKnownWebhookEvents.ApprovalExpired] = LifecycleSubjectTypes.Approval,
    };

    // Logged with no ResourceId, so they never produce a row. Listed so the source scan can tell a
    // deliberate omission from a forgotten one.
    private static readonly HashSet<string> NoSubject = new(StringComparer.Ordinal)
    {
        "SettingsUpdated", "CrlBaseReset", "SecretStorageMigrated", "CaGenerationRequested", "CaImported",
        WellKnownWebhookEvents.RolePermissionsUpdated, WellKnownWebhookEvents.RolePermissionsRenamed,
        "WebhookDestinationModeUpdated", WellKnownWebhookEvents.PqcStageChanged,
        WellKnownWebhookEvents.CaApprovalRuleChanged, WellKnownWebhookEvents.TwoPersonApprovalChanged,
    };

    /// <summary>The subject type for <paramref name="action"/>, or null when it names no resource.</summary>
    public static string? SubjectTypeOf(string action) => Subjects.GetValueOrDefault(action);

    /// <summary>Whether <paramref name="action"/> is accounted for, with or without a subject.</summary>
    public static bool IsKnown(string action) => Subjects.ContainsKey(action) || NoSubject.Contains(action);
}
