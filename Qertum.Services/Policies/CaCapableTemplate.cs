// Qertum.Services/Policies/CaCapableTemplate.cs
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
