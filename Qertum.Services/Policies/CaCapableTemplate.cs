// Qertum.Services/Policies/CaCapableTemplate.cs
using Microsoft.EntityFrameworkCore;

namespace Qertum.Services.Policies;

/// <summary>
/// The single answer to "does this template issue a CA certificate": its key usages include
/// <c>KeyCertSign</c>. The generator (BasicConstraints CA:TRUE), the enrollment purpose classifier,
/// the key-capability rule and the CA permission rule all call this, so what the CA signs and what
/// is guarded cannot drift apart.
/// </summary>
public static class CaCapableTemplate
{
    /// <summary>The key usage that makes a certificate a CA certificate.</summary>
    public const string KeyCertSign = "KeyCertSign";

    /// <summary>True when <paramref name="template"/> asserts <see cref="KeyCertSign"/>; false for null.</summary>
    public static bool IsCaCapable(CertificateTemplate? template) =>
        template is not null && IsCaCapable(template.KeyUsagesJson);

    /// <summary>True when the JSON array of key usages contains <see cref="KeyCertSign"/> (ordinal); malformed JSON is false.</summary>
    public static bool IsCaCapable(string? keyUsagesJson) =>
        IssuancePolicyEvaluator.ReadList(keyUsagesJson).Contains(KeyCertSign, StringComparer.Ordinal);
}

/// <summary>
/// The request types whose certificates are CA certificates: every CA-capable template, plus the root, which has no
/// template. Revoking one retires its issuer (under HardStop with everything below it) and renewing one is a
/// ceremony, so the paths that treat certificates in general (the revoke route, bulk operations, auto-renewal) ask
/// this one question instead of each leaving the root out by accident.
/// </summary>
public static class CaCertificateTypes
{
    /// <summary>The type keys of CA certificates, <see cref="WellKnownCertificateTypes.RootCa"/> included.</summary>
    public static async Task<List<string>> KeysAsync(CertificateRequestDbContext db, CancellationToken cancellationToken = default)
    {
        var templates = await db.CertificateTemplates.AsNoTracking()
            .Select(t => new { t.TypeKey, t.KeyUsagesJson }).ToListAsync(cancellationToken);
        return templates.Where(t => CaCapableTemplate.IsCaCapable(t.KeyUsagesJson)).Select(t => t.TypeKey)
            .Append(WellKnownCertificateTypes.RootCa).ToList();
    }
}

/// <summary>
/// Binds a CA certificate to its approval. Approval checks the CA permission and the independent-approver rule only
/// when the template is CA-capable at that moment, and the queue consumer signs with the template as it is when it
/// signs; between the two, anyone who may edit templates could add <c>KeyCertSign</c> to the template of an approved
/// leaf request and have a subordinate CA issued that nobody approved as one (CWE-367, AI Scan on the 1.0.0-rc5
/// snapshot). The consumer therefore signs from a CA-capable template only a request that was approved as a CA
/// certificate (<see cref="CertificateRequest.ApprovedAsCaCertificate"/>).
/// </summary>
public static class CaApprovalBinding
{
    /// <summary>The violation when <paramref name="template"/> would issue a CA certificate this request was not approved as; else null.</summary>
    public static IssuancePolicyViolation? Check(CertificateRequest request, CertificateTemplate? template) =>
        request.Type != WellKnownCertificateTypes.RootCa && CaCapableTemplate.IsCaCapable(template) && !request.ApprovedAsCaCertificate
            ? new IssuancePolicyViolation(PolicyRules.CaPermission, template!.TypeKey,
                $"Template '{template.TypeKey}' now issues CA certificates, but this request was not approved as one " +
                "(the template was changed after approval, or the request was approved automatically). " +
                "File it again so that someone with the certificates.ca permission approves it.")
            : null;

    /// <summary>A refusing decision carrying <paramref name="violation"/>.</summary>
    public static PolicyDecision Refusal(IssuancePolicyViolation violation) =>
        new(false, null, null, null, [violation]);
}
