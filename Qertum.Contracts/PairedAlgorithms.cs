namespace Qertum.Services;

/// <summary>
/// The two component algorithms of every paired <see cref="CertificateKeyAlgorithm"/>, in one place.
/// The first component is the certificate stored in <c>CertificatePem</c>/<c>PrivateKeyPem</c>, the
/// second the one stored in <c>PqcCertificatePem</c>/<c>PqcPrivateKeyPem</c> (the names predate the
/// pair and stay, so for a signing + encryption pair "Pqc" means "second").
/// </summary>
public static class PairedAlgorithms
{
    private static readonly IReadOnlyDictionary<CertificateKeyAlgorithm, (CertificateKeyAlgorithm First, CertificateKeyAlgorithm Second)> Table =
        new Dictionary<CertificateKeyAlgorithm, (CertificateKeyAlgorithm, CertificateKeyAlgorithm)>
        {
            [CertificateKeyAlgorithm.HybridEcdsaP256] = (CertificateKeyAlgorithm.EcdsaP256, CertificateKeyAlgorithm.MlDsa65),
            [CertificateKeyAlgorithm.HybridEcdsaP384] = (CertificateKeyAlgorithm.EcdsaP384, CertificateKeyAlgorithm.MlDsa87),
            [CertificateKeyAlgorithm.PairMlDsa44MlKem512] = (CertificateKeyAlgorithm.MlDsa44, CertificateKeyAlgorithm.MlKem512),
            [CertificateKeyAlgorithm.PairMlDsa65MlKem768] = (CertificateKeyAlgorithm.MlDsa65, CertificateKeyAlgorithm.MlKem768),
            [CertificateKeyAlgorithm.PairMlDsa87MlKem1024] = (CertificateKeyAlgorithm.MlDsa87, CertificateKeyAlgorithm.MlKem1024)
        };

    /// <summary>The (first, second) component algorithms of <paramref name="algorithm"/>.</summary>
    /// <exception cref="ArgumentException"><paramref name="algorithm"/> is not a paired algorithm.</exception>
    public static (CertificateKeyAlgorithm First, CertificateKeyAlgorithm Second) For(CertificateKeyAlgorithm algorithm) =>
        Table.TryGetValue(algorithm, out var components)
            ? components
            : throw new ArgumentException($"'{algorithm.ToCanonicalString()}' is not a paired algorithm.", nameof(algorithm));

    /// <summary>
    /// The algorithm of one certificate of <paramref name="algorithm"/>: the first or second component of a
    /// paired algorithm, and the algorithm itself for a single-certificate one (it has only one leg).
    /// </summary>
    public static CertificateKeyAlgorithm Leg(CertificateKeyAlgorithm algorithm, bool secondLeg) =>
        Table.TryGetValue(algorithm, out var components) ? (secondLeg ? components.Second : components.First) : algorithm;
}
