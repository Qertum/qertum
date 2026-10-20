using Qertum.Services;

namespace Qertum.Web.Components.Pages;

/// <summary>
/// Wording for the PQC enforcement stage in Settings: what keys stay allowed, and what the stage leaves alone.
/// </summary>
public static class AlgorithmPolicyGuidance
{
    /// <summary>
    /// The algorithms every PQC stage accepts, derived from <see cref="CertificateKeyAlgorithm"/> so a
    /// newly added post-quantum algorithm appears without editing this text. The hand-written list
    /// it replaced said "ML-DSA-65/87" and missed ML-DSA-44 and both SLH-DSA sets.
    /// </summary>
    public static string PqcOnlyAllowedAlgorithms { get; } =
        "a post-quantum algorithm ("
        + string.Join(", ", Enum.GetValues<CertificateKeyAlgorithm>()
            .Where(a => a.GetFamily() == AlgorithmFamily.Pqc)
            .Select(a => a.ToCanonicalString()))
        + "), a paired classical + ML-DSA one, or a composite ML-DSA one — accepted because a composite "
        + "signature is valid only if its ML-DSA half verifies, so it cannot be downgraded to its classical half";

    /// <summary>
    /// What the PQC stage does not change. It governs the keys in certificates this CA issues; operators
    /// otherwise take "PQC-only" to describe the whole deployment.
    /// </summary>
    public const string PqcOnlyScope =
        "This governs the keys in certificates this CA issues, and nothing else. It does not change how "
        + "ACME clients sign their account requests (JWS), how the identity service signs its tokens, or the "
        + "TLS transport and key exchange any of these run over — and it is the key exchange, not the "
        + "certificate, that protects traffic against harvest-now-decrypt-later attacks.";
}
