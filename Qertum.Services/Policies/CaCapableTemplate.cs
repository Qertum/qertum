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
