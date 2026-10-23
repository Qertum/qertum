using Qertum.Services.Crypto.Composite;

namespace Qertum.Web.Components.Pages.Enrollment;

public enum AlgorithmKind
{
    Classical,
    Pqc,
    Hybrid,
    Composite,
    Kem,
    Pair
}

/// <param name="Group">For a composite choice, the classical family it is listed under behind "show all".</param>
/// <param name="Featured">For a composite choice, whether it is shown before "show all".</param>
public sealed record AlgorithmChoice(string Value, string Label, string Note, AlgorithmKind Kind, string? Group = null, bool Featured = false);

/// <summary>Algorithms the key step offers, with the compatibility note shown beside each.</summary>
public static class AlgorithmChoices
{
    private const string PairedNote =
        "Issues two separate certificates from one request — one classical, one ML-DSA. " +
        "This is not a composite certificate and does not provide post-quantum key exchange.";

    private const string PairNote =
        "Issues two separate certificates from one request — an ML-DSA signing certificate and an ML-KEM encryption "
        + "certificate, as S/MIME uses. This is not a composite certificate; the encryption certificate cannot sign "
        + "or authenticate TLS.";

    private const string KemNote =
        "Post-quantum key encapsulation (FIPS 203): others encrypt to this certificate's holder, as S/MIME does. "
        + "The key cannot sign, so the certificate cannot sign mail or code or authenticate TLS.";

    /// <summary>The note beside every composite choice.</summary>
    public const string CompositeNote =
        "One certificate carrying an ML-DSA and a classical key; both signatures must verify. "
        + "Not supported by TLS clients or servers today.";

    /// <summary>
    /// The composite combinations shown before "show all": the same ML-DSA and ECDSA pairings as
    /// paired issuance, so the two formats line up for an operator comparing them.
    /// </summary>
    public static readonly IReadOnlySet<string> FeaturedComposite =
        new HashSet<string>(StringComparer.Ordinal) { "MLDSA65-ECDSA-P256-SHA512", "MLDSA87-ECDSA-P384-SHA512" };

    /// <summary>The order the "show all" groups are listed in: the commonest classical families first.</summary>
    public static readonly IReadOnlyList<string> CompositeGroups =
        ["ECDSA (NIST curves)", "ECDSA (brainpool curves)", "RSA-PSS", "RSA PKCS#1 v1.5", "EdDSA"];

    /// <summary>Position of a group in <see cref="CompositeGroups"/>, for ordering.</summary>
    public static int CompositeGroupOrder(string? group) =>
        CompositeGroups.Select((name, index) => (name, index)).Single(g => g.name == group).index;

    /// <summary>All 18 composite combinations, in the draft's OID order, built from the registry.</summary>
    public static readonly IReadOnlyList<AlgorithmChoice> Composite =
        [.. CompositeAlgorithms.All.Select(a => new AlgorithmChoice(
            a.Name, CompositeLabel(a), CompositeNote, AlgorithmKind.Composite, CompositeGroup(a), FeaturedComposite.Contains(a.Name)))];

    public static readonly IReadOnlyList<AlgorithmChoice> All =
    [
        new("ECDSA-P256", "ECDSA P-256", "Small keys and fast signatures; supported by current TLS clients and servers.", AlgorithmKind.Classical),
        new("ECDSA-P384", "ECDSA P-384", "Larger security margin than P-256 with slightly bigger signatures.", AlgorithmKind.Classical),
        new("RSA", "RSA 2048", "Broadest compatibility, including older clients, mail and code-signing tools.", AlgorithmKind.Classical),
        new("ML-DSA-44", "ML-DSA-44", "Post-quantum signature (FIPS 204, level 2). Smallest ML-DSA keys and signatures; every relying party must support ML-DSA.", AlgorithmKind.Pqc),
        new("ML-DSA-65", "ML-DSA-65", "Post-quantum signature (FIPS 204, level 3). Every relying party must support ML-DSA.", AlgorithmKind.Pqc),
        new("ML-DSA-87", "ML-DSA-87", "Post-quantum signature (FIPS 204, level 5). Larger keys and signatures than ML-DSA-65.", AlgorithmKind.Pqc),
        new("SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S", "Post-quantum hash-based signature (FIPS 205). Conservative design with a tiny public key, but ~8 KB certificates and slow signing.", AlgorithmKind.Pqc),
        new("SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F", "The faster SLH-DSA variant: signing is roughly 20x quicker than 128S, at about double the certificate size.", AlgorithmKind.Pqc),
        new("SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192S", "SLH-DSA at security level 3. ~16 KB certificates and slow signing; suits a long-lived CA key rather than leaves.", AlgorithmKind.Pqc),
        new("SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-192F", "The faster level-3 SLH-DSA variant, at about double the certificate size of 192S (~36 KB).", AlgorithmKind.Pqc),
        new("SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256S", "SLH-DSA at security level 5. ~30 KB certificates and slow signing; suits a long-lived CA key rather than leaves.", AlgorithmKind.Pqc),
        new("SLH-DSA-SHA2-256F", "SLH-DSA-SHA2-256F", "The faster level-5 SLH-DSA variant, at about 50 KB per certificate. Too large for TLS handshakes on most stacks.", AlgorithmKind.Pqc),
        new("ML-KEM-512", "ML-KEM-512", KemNote + " Security category 1.", AlgorithmKind.Kem),
        new("ML-KEM-768", "ML-KEM-768", KemNote + " Security category 3.", AlgorithmKind.Kem),
        new("ML-KEM-1024", "ML-KEM-1024", KemNote + " Security category 5; the parameter set CNSA 2.0 names.", AlgorithmKind.Kem),
        new("HYBRID-ECDSA-P256", "Paired classical + PQC certificates (ECDSA P-256 + ML-DSA-65)", PairedNote, AlgorithmKind.Hybrid),
        new("HYBRID-ECDSA-P384", "Paired classical + PQC certificates (ECDSA P-384 + ML-DSA-87)", PairedNote, AlgorithmKind.Hybrid),
        new("PAIR-ML-DSA-44-ML-KEM-512", "Paired signing + encryption certificates (ML-DSA-44 + ML-KEM-512)", PairNote + " Security level 1–2.", AlgorithmKind.Pair),
        new("PAIR-ML-DSA-65-ML-KEM-768", "Paired signing + encryption certificates (ML-DSA-65 + ML-KEM-768)", PairNote + " Security level 3.", AlgorithmKind.Pair),
        new("PAIR-ML-DSA-87-ML-KEM-1024", "Paired signing + encryption certificates (ML-DSA-87 + ML-KEM-1024)", PairNote + " Security level 5.", AlgorithmKind.Pair),
        .. Composite
    ];

    /// <param name="classicalRefused">
    /// True when the template's PQC stage refuses a new classical request (Pilot or Enforce): only
    /// post-quantum, paired and composite choices are offered.
    /// </param>
    /// <param name="pilotPqc">The wizard's own "pilot post-quantum algorithms" toggle; unrelated to the Pilot stage.</param>
    public static IReadOnlyList<AlgorithmChoice> Visible(bool classicalRefused, bool pilotPqc) =>
        classicalRefused
            ? All.Where(a => a.Kind != AlgorithmKind.Classical).ToList()
            : pilotPqc
                ? All
                : All.Where(a => a.Kind == AlgorithmKind.Classical).ToList();

    public static bool IsClassical(string value) =>
        All.Any(a => a.Value == value && a.Kind == AlgorithmKind.Classical);

    /// <summary>"ML-DSA-65 + ECDSA P-256", read off the registry rather than the name.</summary>
    private static string CompositeLabel(CompositeAlgorithm algorithm) =>
        $"{algorithm.MlDsa.Name} + " + algorithm.Traditional switch
        {
            CompositeTraditional.RsaPss => $"RSA-{algorithm.RsaKeyBits} PSS",
            CompositeTraditional.RsaPkcs15 => $"RSA-{algorithm.RsaKeyBits} PKCS#1 v1.5",
            CompositeTraditional.Ecdsa => "ECDSA " + CurveLabel(algorithm.CurveName),
            CompositeTraditional.Ed25519 => "Ed25519",
            CompositeTraditional.Ed448 => "Ed448",
            var other => throw new ArgumentOutOfRangeException(nameof(algorithm), other, null)
        };

    private static string CompositeGroup(CompositeAlgorithm algorithm) => algorithm.Traditional switch
    {
        CompositeTraditional.Ecdsa when algorithm.CurveName!.StartsWith("brainpool", StringComparison.Ordinal) => "ECDSA (brainpool curves)",
        CompositeTraditional.Ecdsa => "ECDSA (NIST curves)",
        CompositeTraditional.RsaPss => "RSA-PSS",
        CompositeTraditional.RsaPkcs15 => "RSA PKCS#1 v1.5",
        CompositeTraditional.Ed25519 or CompositeTraditional.Ed448 => "EdDSA",
        var other => throw new ArgumentOutOfRangeException(nameof(algorithm), other, null)
    };

    private static string CurveLabel(string? curveName) => curveName switch
    {
        "secp256r1" => "P-256",
        "secp384r1" => "P-384",
        "secp521r1" => "P-521",
        _ => curveName ?? throw new ArgumentNullException(nameof(curveName))
    };
}
