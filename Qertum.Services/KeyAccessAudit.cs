namespace Qertum.Services;

/// <summary>
/// The detail text of the audit entries written when a private key or a PKCS#12 file leaves the server.
/// A signing + encryption pair names the certificate (the second one is not "PQC": both are
/// post-quantum); every other algorithm keeps the wording it always had.
/// </summary>
public static class KeyAccessAudit
{
    /// <summary>Detail of a <c>PrivateKeyDownloaded</c> entry.</summary>
    /// <param name="algorithm">The request's key algorithm, or null when unknown.</param>
    /// <param name="secondLeg">Whether the second certificate's key was downloaded (the <c>pqc</c> flag).</param>
    public static string PrivateKeyDetail(CertificateKeyAlgorithm? algorithm, bool secondLeg) =>
        algorithm?.GetFamily() == AlgorithmFamily.Pair
            ? (secondLeg ? "Encryption private key" : "Signing private key")
            : (secondLeg ? "PQC private key" : "Private key");

    /// <summary>Detail of a <c>PfxExported</c> entry.</summary>
    /// <param name="algorithm">The request's key algorithm, or null when unknown.</param>
    /// <param name="secondLeg">Whether the second certificate was exported (the <c>pqc</c> flag).</param>
    /// <param name="includeChain">Whether the CA chain was included.</param>
    public static string PfxDetail(CertificateKeyAlgorithm? algorithm, bool secondLeg, bool includeChain)
    {
        var certificate = algorithm?.GetFamily() == AlgorithmFamily.Pair
            ? (secondLeg ? " (encryption certificate)" : " (signing certificate)")
            : string.Empty;
        return $"PKCS#12{certificate}{(includeChain ? " with CA chain" : string.Empty)}";
    }
}
