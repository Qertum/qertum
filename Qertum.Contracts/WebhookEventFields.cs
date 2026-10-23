namespace Qertum.Services;

/// <summary>
/// The fields a webhook event may carry, per family. This is the ONLY source for both the delivery
/// body's <c>data</c> object and <c>{placeholder}</c> substitution in a webhook URL, and it is
/// deliberately an explicit list: never replace it with reflection over an entity, or key material
/// and secrets become reachable by naming a property.
/// </summary>
public static class WebhookEventFields
{
    /// <summary>Available to every family except where a family suppresses one (see <see cref="All"/>).</summary>
    public static readonly IReadOnlySet<string> Common = new HashSet<string>(StringComparer.Ordinal)
    {
        "event", "family", "timestamp", "performedBy", "resourceId", "resourceName"
    };

    private static readonly IReadOnlySet<string> None = new HashSet<string>(StringComparer.Ordinal);

    private static readonly Dictionary<WebhookEventFamily, IReadOnlySet<string>> FamilyFields = new()
    {
        [WebhookEventFamily.CertificateRequest] = new HashSet<string>(StringComparer.Ordinal)
        {
            "commonName", "status", "certificateType", "keyAlgorithm",
            "serialNumber", "validTo", "failureReason", "requestedBy"
            ,
            "ownerTeam", "targetSystem", "ticketReference", "purpose"
        },
        [WebhookEventFamily.Settings] = new HashSet<string>(StringComparer.Ordinal)
        {
            "role", "grantedPermissions", "revokedPermissions", "previousRole", "previousStage", "stage",
            "typeKey", "namePattern", "family", "expiresAtUtc", "approvalMode", "previousApprovalMode", "twoPersonApproval", "previousMode", "mode"
        },
        [WebhookEventFamily.Template] = new HashSet<string>(StringComparer.Ordinal)
        {
            "templateName", "typeKey", "issuancePolicyId", "issuerId", "pqcStage"
        },
        [WebhookEventFamily.Policy] = new HashSet<string>(StringComparer.Ordinal)
        {
            "policyName", "versionNumber", "versionStatus"
        },
        [WebhookEventFamily.KeyAccess] = new HashSet<string>(StringComparer.Ordinal)
        {
            "publicKeyThumbprint"
        },
        [WebhookEventFamily.Issuer] = new HashSet<string>(StringComparer.Ordinal)
        {
            "issuerId", "issuerName", "kind", "status", "subjectDn", "validTo", "affectedCertificateCount"
        },
        [WebhookEventFamily.BulkOperation] = new HashSet<string>(StringComparer.Ordinal)
        {
            "operationId", "kind", "status", "itemCount", "doneCount", "skippedCount", "failedCount"
        },
        [WebhookEventFamily.Notice] = new HashSet<string>(StringComparer.Ordinal)
        {
            "commonName", "validTo", "daysLeft", "level", "renewalId", "failureReason",
            "ownerTeam", "contactEmail", "targetSystem", "ticketReference"
        },
        [WebhookEventFamily.Audit] = new HashSet<string>(StringComparer.Ordinal)
        {
            "generatedAt", "chainCount", "heads"
        },
        [WebhookEventFamily.Approval] = new HashSet<string>(StringComparer.Ordinal)
        {
            "approvalId", "operation", "targetId", "requestedBy", "decidedBy", "status", "grantExpiresAtUtc"
        }
    };

    /// <summary>
    /// Fields <see cref="WebhookEventFamily.KeyAccess"/> does not carry. A key-egress event names the
    /// exported key by thumbprint and nothing else: the certificate's common name and its request id
    /// stay in the audit log rather than reaching an external endpoint or an access log.
    /// </summary>
    private static readonly IReadOnlySet<string> KeyAccessSuppressed = new HashSet<string>(StringComparer.Ordinal)
    {
        "resourceId", "resourceName"
    };

    /// <summary>The family-specific fields, excluding the common set.</summary>
    public static IReadOnlySet<string> For(WebhookEventFamily family) => FamilyFields[family];

    /// <summary>Every field the family may carry: the common set minus its suppressions, plus its own.</summary>
    public static IReadOnlySet<string> All(WebhookEventFamily family)
    {
        var suppressed = family == WebhookEventFamily.KeyAccess ? KeyAccessSuppressed : None;
        return Common.Where(f => !suppressed.Contains(f))
            .Concat(FamilyFields[family])
            .ToHashSet(StringComparer.Ordinal);
    }

    /// <summary>Whether <paramref name="field"/> is available to <paramref name="family"/>.</summary>
    public static bool IsKnown(WebhookEventFamily family, string field) => All(family).Contains(field);

    /// <summary>Whether the family suppresses the common field <paramref name="field"/>.</summary>
    public static bool IsSuppressed(WebhookEventFamily family, string field) =>
        family == WebhookEventFamily.KeyAccess && KeyAccessSuppressed.Contains(field);
}
