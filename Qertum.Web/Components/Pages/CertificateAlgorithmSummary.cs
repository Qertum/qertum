using Qertum.Services;

namespace Qertum.Web.Components.Pages;

/// <summary>
/// Separates the two algorithm facts a certificate carries: the algorithm of the subject's own
/// public key, and the algorithm the issuer signed with.
/// </summary>
/// <remarks>
/// <para>
/// These are independent. A classical CA can sign a certificate holding an ML-DSA subject key, and
/// a post-quantum CA can sign one holding an RSA key; neither combination makes the certification
/// path post-quantum on its own. The detail page previously showed a single field labelled
/// "Signature Algorithm", which is the issuer's — so an ML-DSA leaf under the RSA CA read as an
/// RSA certificate.
/// </para>
/// <para>
/// The post-quantum signature OIDs are listed in <see cref="CertificateSignatureAlgorithms"/>
/// because .NET's <c>Oid.FriendlyName</c> is empty
/// for every one of them, which would otherwise render the field blank. They are pinned to what
/// <c>CertificateGenerator</c> actually writes by
/// <c>CertificateAlgorithmSummaryTests.IssuerSignatureLabel_NamesThePqcAlgorithmARealCertificateWasSignedWith</c>,
/// which issues a real leaf under each CA algorithm and reads the OID back off it rather than
/// trusting a constant copied from a specification.
/// </para>
/// </remarks>
public static class CertificateAlgorithmSummary
{
    /// <summary>Shown where an algorithm is genuinely not known, in place of a guess.</summary>
    public const string Unknown = "Unknown";

    /// <summary>
    /// What paired issuance (<see cref="AlgorithmFamily.Hybrid"/>) does not give. A pair is two
    /// ordinary certificates for one subject, and "hybrid" invites the reading that it resists the
    /// break of either algorithm — which is what a composite certificate does, and a pair does not.
    /// Shown wherever a pair is chosen or shown, and echoed by <c>qca cert download-cert</c>.
    /// </summary>
    public const string PairedIssuanceScopeNote =
        "A paired bundle is two independent certificates, not a composite certificate: a relying party "
        + "validates one of them, so an attacker only needs to break the one it accepts. It also does not "
        + "provide hybrid TLS authentication — a TLS handshake presents one certificate.";

    /// <summary>
    /// What a signing + encryption pair is and is not. Shown wherever a pair is chosen or shown, and
    /// echoed by <c>qca cert download-cert</c>. The hybrid wording (<see cref="PairedIssuanceScopeNote"/>)
    /// does not fit: neither certificate here is classical, and one of them cannot sign.
    /// </summary>
    public const string PairScopeNote =
        "A signing and encryption pair is two independent certificates, not a composite certificate: the ML-DSA "
        + "certificate signs, and the ML-KEM certificate lets others encrypt to its holder (CMS KEMRecipientInfo, as "
        + "S/MIME uses). Neither provides hybrid TLS authentication, and the ML-KEM key cannot sign, so the "
        + "encryption certificate cannot sign mail or code or authenticate a TLS client or server.";

    // Composite ML-DSA OIDs come from the Contracts table, so a new combination is named here too.
    /// <summary>
    /// What a composite ML-DSA certificate is and is not. It is the one hybrid format that cannot be
    /// downgraded, which invites the reading that it works anywhere a classical certificate does —
    /// and no TLS stack negotiates a composite signature yet. Echoed by <c>qca cert download-cert</c>.
    /// </summary>
    public const string CompositeScopeNote =
        "A composite certificate holds one ML-DSA key and one classical key under a single algorithm, and its "
        + "signature is valid only if both halves verify — it is not paired issuance. Only composite-aware "
        + "software can use it: no TLS client or server negotiates a composite signature today.";

    /// <summary>
    /// Shown before a composite root is generated, and confirmed before Generate is enabled. A
    /// composite root cannot be validated by anything that lacks composite support, and unlike a
    /// Catalyst-style certificate it offers no classical fallback — the choice is all-or-nothing and
    /// only undone by replacing the root.
    /// </summary>
    public const string CompositeRootNotice =
        "Every relying party must support composite ML-DSA to validate anything this CA issues — its "
        + "certificates, its CRL and its OCSP responses. A client without composite support cannot fall back to "
        + "the classical half, and changing this later means replacing the root and redistributing trust.";

    /// <summary>
    /// What an ML-KEM certificate is for and what it cannot do. A KEM key establishes keys and
    /// cannot sign, which a "post-quantum" badge alone does not tell anyone; the note names only the
    /// use the interop run measured (CMS encryption) and never
    /// claims TLS, which no stack supports with a KEM certificate. Rendered on the detail page, on
    /// the key step when ML-KEM is chosen, and echoed word for word by <c>qca cert download-cert</c>.
    /// </summary>
    public const string KemScopeNote =
        "An ML-KEM certificate lets others encrypt to its holder: CMS KEMRecipientInfo (RFC 9629), as S/MIME "
        + "uses. Its key cannot sign, so it cannot sign mail or code, and it cannot authenticate a TLS client or "
        + "server — no TLS stack uses ML-KEM certificates. Tested for CMS encryption with OpenSSL 3.6 and "
        + "BouncyCastle Java 1.86.";

    private static readonly IReadOnlyDictionary<string, string> PostQuantumSignatureOids =
        CertificateSignatureAlgorithms.PostQuantumSignatureOids;

    /// <summary>
    /// The algorithm of the subject's public key, for the certificate currently being shown.
    /// </summary>
    /// <param name="algorithm">The request's stored <see cref="CertificateKeyAlgorithm"/>.</param>
    /// <param name="pqcLeg">
    /// For paired issuance, whether the certificate being labelled is the PQC one. Paired issuance
    /// writes two certificates and neither of them holds a "hybrid" key, so the pair's own name
    /// would misname whichever one is on screen.
    /// </param>
    public static string SubjectKeyLabel(CertificateKeyAlgorithm? algorithm, bool pqcLeg) => algorithm switch
    {
        null => Unknown,
        // A pair's own name would misname whichever certificate is on screen: show that leg's key.
        { } paired when paired.IsPaired() => PairedAlgorithms.Leg(paired, pqcLeg).ToCanonicalString(),
        _ => algorithm.Value.ToCanonicalString()
    };

    /// <summary>
    /// The post-quantum scheme a PQC-only algorithm belongs to (<c>ML-DSA</c>, <c>SLH-DSA</c> or <c>ML-KEM</c>), for
    /// badges and notes that name the scheme rather than the parameter set.
    /// </summary>
    /// <returns>The scheme name, or null for a classical or paired algorithm.</returns>
    /// <remarks>
    /// The badges used to say "ML-DSA" for every PQC-only certificate, which misnamed each SLH-DSA
    /// one from the day SLH-DSA shipped.
    /// </remarks>
    public static string? PqcSchemeName(CertificateKeyAlgorithm? algorithm) => algorithm switch
    {
        CertificateKeyAlgorithm.MlDsa44 or CertificateKeyAlgorithm.MlDsa65 or CertificateKeyAlgorithm.MlDsa87 => "ML-DSA",
        CertificateKeyAlgorithm.SlhDsaSha2128s or CertificateKeyAlgorithm.SlhDsaSha2128f => "SLH-DSA",
        CertificateKeyAlgorithm.MlKem512 or CertificateKeyAlgorithm.MlKem768 or CertificateKeyAlgorithm.MlKem1024 => "ML-KEM",
        _ => null
    };

    /// <summary>
    /// The algorithm the issuer signed this certificate with, read from the certificate itself.
    /// </summary>
    /// <param name="oid">The signature algorithm OID.</param>
    /// <param name="friendlyName">The platform's name for it, which is empty for PQC algorithms.</param>
    /// <returns>
    /// A canonical post-quantum name, the platform's friendly name, or the raw OID — an
    /// unrecognized OID is still a fact the operator can look up, where a blank field is not.
    /// </returns>
    public static string IssuerSignatureLabel(string? oid, string? friendlyName)
    {
        if (oid is not null && PostQuantumSignatureOids.TryGetValue(oid, out var canonical))
            return canonical;
        if (!string.IsNullOrWhiteSpace(friendlyName))
            return friendlyName;
        return string.IsNullOrWhiteSpace(oid) ? Unknown : oid;
    }

    /// <summary>The family label on a request's algorithm badge.</summary>
    public static string FamilyLabel(CertificateKeyAlgorithm algorithm) => algorithm.GetFamily() switch
    {
        AlgorithmFamily.Pqc => $"Full PQC · {PqcSchemeName(algorithm)}",
        AlgorithmFamily.Hybrid => "Hybrid · Classical + PQC",
        AlgorithmFamily.Composite => "Composite · ML-DSA + classical",
        AlgorithmFamily.Kem => $"Full PQC · {PqcSchemeName(algorithm)} (encryption)",
        AlgorithmFamily.Pair => "Pair · Signing + Encryption",
        AlgorithmFamily.Ecdsa => "Classical · ECDSA",
        AlgorithmFamily.Rsa => "Classical · RSA",
        var family => throw new ArgumentOutOfRangeException(nameof(algorithm), family, null)
    };

    /// <summary>The CSS class of a request's algorithm badge (<c>.algorithm-badge-*</c> in app.css).</summary>
    public static string FamilyBadgeClass(CertificateKeyAlgorithm algorithm) => algorithm.GetFamily() switch
    {
        AlgorithmFamily.Pqc => "algorithm-badge-pqc",
        AlgorithmFamily.Hybrid => "algorithm-badge-hybrid",
        AlgorithmFamily.Composite => "algorithm-badge-composite",
        AlgorithmFamily.Kem => "algorithm-badge-kem",
        AlgorithmFamily.Pair => "algorithm-badge-pair",
        AlgorithmFamily.Ecdsa => "algorithm-badge-ecdsa",
        AlgorithmFamily.Rsa => "algorithm-badge-rsa",
        var family => throw new ArgumentOutOfRangeException(nameof(algorithm), family, null)
    };

    /// <summary>Whether the subject key of the certificate being shown is post-quantum.</summary>
    public static bool SubjectIsPostQuantum(CertificateKeyAlgorithm? algorithm, bool pqcLeg) => algorithm switch
    {
        null => false,
        _ => algorithm.Value.GetFamily() switch
        {
            AlgorithmFamily.Pqc => true,
            // A composite key holds an ML-DSA component, and its signature needs both halves.
            AlgorithmFamily.Composite => true,
            // An ML-KEM key is post-quantum; it establishes keys rather than verifying signatures.
            AlgorithmFamily.Kem => true,
            // Both certificates of a signing + encryption pair carry a post-quantum key.
            AlgorithmFamily.Pair => true,
            // Only the PQC half of a pair carries a post-quantum key; the classical certificate is
            // classical however the pair is labelled.
            AlgorithmFamily.Hybrid => pqcLeg,
            _ => false
        }
    };

    /// <summary>Whether a signature algorithm OID is a post-quantum one.</summary>
    public static bool IssuerIsPostQuantum(string? oid) =>
        oid is not null && PostQuantumSignatureOids.ContainsKey(oid);

    /// <summary>
    /// Plain-language explanation of what the two algorithms together do and do not provide.
    /// Empty when both halves are classical, where there is nothing to correct.
    /// </summary>
    /// <param name="subjectIsPostQuantum">Whether the subject key is post-quantum.</param>
    /// <param name="issuerIsPostQuantum">Whether the issuer signature is post-quantum.</param>
    /// <param name="subjectIsKem">
    /// Whether the subject key is ML-KEM. A KEM key establishes keys rather than signing, so the
    /// signature-key wording ("covers authentication only: no post-quantum key exchange") is wrong
    /// for it; the KEM case says what it does give — CMS key establishment — and not TLS.
    /// </param>
    public static string CertificationPathNote(bool subjectIsPostQuantum, bool issuerIsPostQuantum, bool subjectIsKem = false) =>
        (subjectIsKem, issuerIsPostQuantum) switch
        {
            (true, false) =>
                "This certificate's key is a post-quantum ML-KEM key, which others use to encrypt to its holder, but "
                + "the issuer signed it with a classical key: the binding of this key to this name rests on a classical "
                + "signature, so an adversary able to break the issuer's algorithm could substitute a key of their own.",
            (true, true) =>
                "This certificate's key is a post-quantum ML-KEM key and the issuer signature over it is post-quantum "
                + "too, so both encrypting to this certificate and trusting that the key belongs to this name rest on "
                + "post-quantum algorithms. That is CMS key establishment only; it does not change TLS key exchange.",
            _ => SignatureKeyPathNote(subjectIsPostQuantum, issuerIsPostQuantum)
        };

    private static string SignatureKeyPathNote(bool subjectIsPostQuantum, bool issuerIsPostQuantum) =>
        (subjectIsPostQuantum, issuerIsPostQuantum) switch
        {
            (true, false) =>
                "This certificate's subject key is post-quantum, but the issuer signed it with a classical "
                + "key, so the certification path is not fully post-quantum — an adversary able to break the "
                + "issuer's algorithm can still forge a path to this name.",
            (false, true) =>
                "The issuer signature is post-quantum, but this certificate's own subject key is classical, "
                + "so the path is not fully post-quantum.",
            (true, true) =>
                "Both the subject key and the issuer signature are post-quantum, so the certification path "
                + "is post-quantum end to end. That covers authentication only: it does not provide "
                + "post-quantum key exchange, and does not change the TLS transport this certificate is "
                + "served over.",
            (false, false) => string.Empty
        };

    /// <summary>
    /// What the algorithm being chosen will and will not give, given the CA that will sign it.
    /// Empty when there is nothing to correct, and empty when the issuer algorithm is unknown —
    /// a CA key with no <see cref="CertificateKeyAlgorithm"/> value leaves
    /// <c>CaStatusResponse.Algorithm</c> null, and calling that "classical" would assert something
    /// nobody established.
    /// </summary>
    /// <param name="selectedAlgorithm">Canonical name of the algorithm the requester picked.</param>
    /// <param name="caAlgorithm">Canonical name of the CA key, from <c>GET /ca/status</c>.</param>
    public static string EnrollmentPathNote(string? selectedAlgorithm, string? caAlgorithm)
    {
        if (CertificateKeyAlgorithmExtensions.Parse(caAlgorithm) is not { } issuer)
            return string.Empty;

        // A paired choice produces a post-quantum certificate as one of its two legs, so it raises
        // the same question as a straight PQC choice.
        var subjectIsPostQuantum = CertificateKeyAlgorithmExtensions.Parse(selectedAlgorithm)?.GetFamily()
            is AlgorithmFamily.Pqc or AlgorithmFamily.Hybrid or AlgorithmFamily.Composite or AlgorithmFamily.Pair;
        var issuerIsPostQuantum = issuer.GetFamily() is AlgorithmFamily.Pqc or AlgorithmFamily.Composite;
        var issuerName = issuer.ToCanonicalString();

        if (CertificateKeyAlgorithmExtensions.Parse(selectedAlgorithm)?.GetFamily() == AlgorithmFamily.Kem)
            return issuerIsPostQuantum
                ? $"This CA signs with {issuerName}, so both the ML-KEM key you have chosen and the signature binding it "
                  + "to this name are post-quantum. That covers CMS key establishment only; it does not change TLS key exchange."
                : $"This CA signs with {issuerName}: the ML-KEM key you have chosen is post-quantum, but the issuer "
                  + "signature binding it to this name is not.";

        return (subjectIsPostQuantum, issuerIsPostQuantum) switch
        {
            (true, false) =>
                $"This CA signs with {issuerName}, so the certification path is not fully post-quantum: "
                + "the key in the issued certificate is post-quantum, but the issuer signature over it is not.",
            (false, true) =>
                $"This CA signs with {issuerName}, but the key you have chosen is classical, so the "
                + "certification path is not fully post-quantum.",
            (true, true) =>
                $"This CA signs with {issuerName}, so the certification path will be post-quantum end to end. "
                + "That covers authentication only: it does not provide post-quantum key exchange, and does "
                + "not change the TLS transport the certificate is served over.",
            (false, false) => string.Empty
        };
    }
}
