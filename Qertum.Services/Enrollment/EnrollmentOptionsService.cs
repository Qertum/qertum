using Microsoft.EntityFrameworkCore;
using Qertum.Services.Policies;

namespace Qertum.Services.Enrollment;

/// <summary>Builds the enrollment wizard's options. Read-only.</summary>
public interface IEnrollmentOptionsService
{
    Task<EnrollmentOptionsResponse> GetAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// As <see cref="GetAsync(CancellationToken)"/>, leaving out templates whose published policy
    /// lists requester roles <paramref name="requester"/> holds none of. Null = unfiltered.
    /// </summary>
    Task<EnrollmentOptionsResponse> GetAsync(RequesterRoles? requester, CancellationToken cancellationToken = default);

    /// <summary>
    /// As the requester overload, additionally leaving out templates <paramref name="caller"/> may not
    /// use under <see cref="CaPermissionRule"/>. Null = unfiltered.
    /// </summary>
    Task<EnrollmentOptionsResponse> GetAsync(RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default);
}

internal sealed class EnrollmentOptionsService(
    CertificateRequestDbContext db,
    EnrollmentDisplayUrls urls) : IEnrollmentOptionsService
{
    private const string DefaultProtocolTemplate = "WebServer";

    /// <summary>
    /// Whether this caller could submit under <paramref name="version"/> at all. Key custody is
    /// checked for everyone, admin included: <c>CsrPem</c> is pipeline-only, so no REST, wizard or
    /// CLI submission carries a client-generated key and no role bypasses that. The requester-role
    /// rule is submission-role-based, so it is skipped for admin and for callers with no roles to
    /// judge (ACME, EST and the unauthenticated overload).
    /// </summary>
    private static bool Admits(IssuancePolicyVersion version, RequesterRoles? requester)
    {
        if (!KeyCustodyRule.AdmitsCaGeneratedKey(version)) return false;
        if (requester is null || requester.IsAdmin) return true;
        return RequesterRoleRule.Admits(version, requester, out _);
    }

    public Task<EnrollmentOptionsResponse> GetAsync(CancellationToken cancellationToken = default)
        => GetAsync(requester: null, cancellationToken);

    public Task<EnrollmentOptionsResponse> GetAsync(RequesterRoles? requester, CancellationToken cancellationToken = default)
        => GetAsync(requester, caller: null, cancellationToken);

    public async Task<EnrollmentOptionsResponse> GetAsync(RequesterRoles? requester, CallerContext? caller, CancellationToken cancellationToken = default)
    {
        // Read-only on purpose: GetSettingsAsync inserts the singleton row when it is missing.
        var settings = await db.Settings.AsNoTracking().FirstOrDefaultAsync(s => s.Id == 1, cancellationToken);
        var templates = await db.CertificateTemplates.AsNoTracking().OrderBy(t => t.Name).ToListAsync(cancellationToken);

        // The same admission test the evaluator applies, so the wizard never offers a template create would refuse.
        if (caller is not null)
            templates = templates.Where(t => CaPermissionRule.Admits(t, caller)).ToList();

        var linkedIds = templates.Where(t => t.IssuancePolicyId is not null).Select(t => t.IssuancePolicyId!.Value).ToList();
        if (linkedIds.Count > 0)
        {
            // The same admission tests the evaluator applies at submission, so the wizard never
            // offers a template the create would refuse.
            var published = await db.IssuancePolicyVersions.AsNoTracking()
                .Where(v => linkedIds.Contains(v.PolicyId) && v.Status == IssuancePolicyVersionStatus.Published)
                .ToListAsync(cancellationToken);

            templates = templates.Where(t => t.IssuancePolicyId is not { } policyId
                || published.FirstOrDefault(v => v.PolicyId == policyId) is not { } version
                || Admits(version, requester)).ToList();
        }

        // Built field by field: this response is an allowlist, pinned by a test.
        var summaries = templates.Select(t => new EnrollmentTemplateSummary
        {
            TypeKey = t.TypeKey,
            Name = t.Name,
            Description = t.Description,
            SanTypes = EnrollmentPurposeClassifier.ParseStringArray(t.SanTypesJson),
            DefaultValidityDays = ValidityDefaults.EffectiveValidityDays(t, settings),
            Purposes = EnrollmentPurposeClassifier.Classify(t.KeyUsagesJson, t.ExtendedKeyUsagesJson),
            PqcStage = t.PqcStageOverride ?? (settings?.PqcStage ?? PqcStage.Enforce)
        }).ToList();

        var purposes = Enum.GetValues<EnrollmentPurpose>()
            .Select(purpose => new EnrollmentPurposeOption
            {
                Purpose = purpose,
                TemplateTypeKeys = summaries.Where(s => s.Purposes.Contains(purpose)).Select(s => s.TypeKey).ToList()
            })
            .Where(option => option.TemplateTypeKeys.Count > 0)
            .ToList();

        return new EnrollmentOptionsResponse
        {
            Purposes = purposes,
            Templates = summaries,
            PqcStage = settings?.PqcStage ?? PqcStage.Enforce,
            Acme = urls.AcmeDirectoryUrl is { } acmeUrl
                ? new AcmeEnrollmentRoute
                {
                    TemplateTypeKey = TemplateKeyOrDefault(settings?.AcmeTemplateTypeKey),
                    DirectoryUrl = acmeUrl,
                    ExternalAccountBindingRequired = settings?.AcmeRequireExternalAccountBinding ?? false,
                    AutoApprove = settings?.AcmeAutoApprove ?? false
                }
                : null,
            Est = urls.EstBaseUrl is { } estUrl
                ? new EstEnrollmentRoute
                {
                    TemplateTypeKey = TemplateKeyOrDefault(settings?.EstTemplateTypeKey),
                    BaseUrl = estUrl,
                    AutoApprove = settings?.EstAutoApprove ?? false
                }
                : null
        };
    }

    // Matches how ACME and EST read their keys: an empty value still files under WebServer.
    private static string TemplateKeyOrDefault(string? key) =>
        string.IsNullOrWhiteSpace(key) ? DefaultProtocolTemplate : key;
}
