using Qertum.Services;
using System.Security.Cryptography.X509Certificates;

namespace Qertum.Cli.Commands;

/// <summary>
/// The CLI's copy of <c>Qertum.Web.Components.Pages.CertificateAlgorithmSummary</c>: reports the
/// subject key algorithm and the issuer signature algorithm as two facts, never one.
/// </summary>
/// <remarks>
/// The CLI takes no Web project reference, so display notes remain duplicated and pinned to the Web
/// copy by <c>CertificateAlgorithmLinesTests</c>. Signature OIDs come from Contracts. Algorithms arrive as canonical wire strings
/// (<c>"ML-DSA-65"</c>), not as the enum.
/// </remarks>
internal static class CertificateAlgorithmLines
{
    internal const string Unknown = "Unknown";

    /// <summary>
    /// .NET's <c>Oid.FriendlyName</c> is empty for every post-quantum signature OID, so without this
    /// shared table a PQC-signed certificate would print a bare OID.
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, string> PostQuantumSignatureOids =
        Qertum.Services.CertificateSignatureAlgorithms.PostQuantumSignatureOids;

    internal const string CompositeScopeNote =
        "A composite certificate holds one ML-DSA key and one classical key under a single algorithm, and its "
        + "signature is valid only if both halves verify — it is not paired issuance. Only composite-aware "
        + "software can use it: no TLS client or server negotiates a composite signature today.";

    internal const string CompositePkcs12Note =
        "This file carries the composite ML-DSA private key, but .NET on macOS and OpenSSL 3.6 cannot import "
        + "a composite key from PKCS#12 — only composite-aware software can. For most targets, download the "
        + "certificate and private key as separate PEM files.";

    internal const string PqcPkcs12Note =
        "This file carries the ML-DSA or SLH-DSA private key in its standard encoding (RFC 9881, RFC 9909). "
        + "OpenSSL 3.6 imports it; .NET on macOS does not. If your target cannot, download the certificate and "
        + "private key as separate PEM files.";

    internal const string KemPkcs12Note =
        "This file carries the ML-KEM private key in its standard PKCS#8 encoding. OpenSSL 3.6 and BouncyCastle "
        + "Java 1.86 import it; .NET on macOS does not. If your target cannot, download the certificate and private "
        + "key as separate PEM files.";

    /// <summary>
    /// The line <c>download-cert -F pfx</c> prints to stderr before the file, or null for a
    /// classical key. <paramref name="pqcLeg"/> is <c>--pqc</c>, which exports the ML-DSA
    /// certificate of a pair — PQC-only too, whatever the pair is called.
    /// </summary>
    internal static string? Pkcs12Note(string? keyAlgorithm, bool pqcLeg) =>
        // Each certificate of a pair exports with the importer note of its own key.
        IsPair(keyAlgorithm) ? (pqcLeg ? $"note: {KemPkcs12Note}" : $"note: {PqcPkcs12Note}")
        : !pqcLeg && IsComposite(keyAlgorithm) ? $"warning: {CompositePkcs12Note}"
        : !pqcLeg && IsKem(keyAlgorithm) ? $"note: {KemPkcs12Note}"
        : pqcLeg || IsPqcOnly(keyAlgorithm) ? $"note: {PqcPkcs12Note}"
        : null;

    internal const string KemScopeNote =
        "An ML-KEM certificate lets others encrypt to its holder: CMS KEMRecipientInfo (RFC 9629), as S/MIME "
        + "uses. Its key cannot sign, so it cannot sign mail or code, and it cannot authenticate a TLS client or "
        + "server — no TLS stack uses ML-KEM certificates. Tested for CMS encryption with OpenSSL 3.6 and "
        + "BouncyCastle Java 1.86.";

    /// <summary>True for an ML-KEM wire string: <c>ML-KEM-512</c>, <c>-768</c> or <c>-1024</c>.</summary>
    internal static bool IsKem(string? keyAlgorithm) =>
        keyAlgorithm?.StartsWith("ML-KEM-", StringComparison.Ordinal) == true;

    /// <summary>True for a PQC-only wire string: an ML-DSA or SLH-DSA parameter set.</summary>
    internal static bool IsPqcOnly(string? keyAlgorithm) =>
        keyAlgorithm is not null
        && (keyAlgorithm.StartsWith("ML-DSA-", StringComparison.Ordinal) || keyAlgorithm.StartsWith("SLH-DSA-", StringComparison.Ordinal));

    /// <summary>True for a composite ML-DSA wire string such as <c>MLDSA65-ECDSA-P256-SHA512</c>.</summary>
    internal static bool IsComposite(string? keyAlgorithm) =>
        keyAlgorithm?.StartsWith("MLDSA", StringComparison.Ordinal) == true;

    internal const string PairScopeNote =
        "A signing and encryption pair is two independent certificates, not a composite certificate: the ML-DSA "
        + "certificate signs, and the ML-KEM certificate lets others encrypt to its holder (CMS KEMRecipientInfo, as "
        + "S/MIME uses). Neither provides hybrid TLS authentication, and the ML-KEM key cannot sign, so the "
        + "encryption certificate cannot sign mail or code or authenticate a TLS client or server.";

    /// <summary>True for a signing + encryption pair wire string: <c>PAIR-ML-DSA-65-ML-KEM-768</c> and its siblings.</summary>
    internal static bool IsPair(string? keyAlgorithm) =>
        CertificateKeyAlgorithmExtensions.Parse(keyAlgorithm)?.GetFamily() == AlgorithmFamily.Pair;

    /// <summary>
    /// The wire string of the certificate being described: that leg's component for a signing + encryption
    /// pair, and the stored algorithm for everything else (a hybrid keeps its existing labelling).
    /// </summary>
    internal static string? LegAlgorithm(string? keyAlgorithm, bool pqcLeg) =>
        CertificateKeyAlgorithmExtensions.Parse(keyAlgorithm) is { } parsed && parsed.GetFamily() == AlgorithmFamily.Pair
            ? PairedAlgorithms.Leg(parsed, pqcLeg).ToCanonicalString()
            : keyAlgorithm;

    internal const string PairedIssuanceScopeNote =
        "A paired bundle is two independent certificates, not a composite certificate: a relying party "
        + "validates one of them, so an attacker only needs to break the one it accepts. It also does not "
        + "provide hybrid TLS authentication — a TLS handshake presents one certificate.";

    /// <summary>
    /// The subject key of the certificate being described. A paired request resolves to the leg
    /// actually downloaded, because neither certificate of a pair holds a "hybrid" key.
    /// </summary>
    internal static string SubjectKeyLabel(string? keyAlgorithm, bool pqcLeg) => keyAlgorithm switch
    {
        null or "" => Unknown,
        "HYBRID-ECDSA-P256" => pqcLeg ? "ML-DSA-65" : "ECDSA-P256",
        "HYBRID-ECDSA-P384" => pqcLeg ? "ML-DSA-87" : "ECDSA-P384",
        _ when IsPair(keyAlgorithm) => LegAlgorithm(keyAlgorithm, pqcLeg)!,
        _ => keyAlgorithm
    };

    internal static bool SubjectIsPostQuantum(string? keyAlgorithm, bool pqcLeg) =>
        keyAlgorithm is not null
        && (keyAlgorithm.StartsWith("ML-DSA-", StringComparison.Ordinal)
            || keyAlgorithm.StartsWith("SLH-DSA-", StringComparison.Ordinal)
            || keyAlgorithm.StartsWith("ML-KEM-", StringComparison.Ordinal)
            // Composite ML-DSA ("MLDSA65-ECDSA-P256-SHA512"): the key holds an ML-DSA component.
            || keyAlgorithm.StartsWith("MLDSA", StringComparison.Ordinal)
            // Both certificates of a signing + encryption pair are post-quantum.
            || IsPair(keyAlgorithm)
            || (pqcLeg && keyAlgorithm.StartsWith("HYBRID-", StringComparison.Ordinal)));

    /// <summary>
    /// Lines describing a downloaded certificate: subject key, issuer signature, and a note when
    /// the combination claims less (or more) than an operator might assume.
    /// </summary>
    internal static IReadOnlyList<string> Describe(string? keyAlgorithm, bool pqcLeg, string certificatePem)
    {
        string? signatureOid = null;
        string issuerLabel;
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            signatureOid = certificate.SignatureAlgorithm.Value;
            issuerLabel = IssuerSignatureLabel(signatureOid, certificate.SignatureAlgorithm.FriendlyName);
        }
        catch (Exception ex) when (ex is ArgumentException or System.Security.Cryptography.CryptographicException)
        {
            issuerLabel = Unknown;
        }

        var lines = new List<string>
        {
            Line("subject key", SubjectKeyLabel(keyAlgorithm, pqcLeg)),
            Line("issuer signature", issuerLabel)
        };

        var leg = LegAlgorithm(keyAlgorithm, pqcLeg);
        var subjectPqc = SubjectIsPostQuantum(keyAlgorithm, pqcLeg);
        var issuerPqc = signatureOid is not null && PostQuantumSignatureOids.ContainsKey(signatureOid);
        var pathNote = (IsKem(leg), issuerPqc) switch
        {
            // A KEM key establishes keys; the signature-key wording below would deny exactly that.
            (true, false) => "not a fully post-quantum certification path: the ML-KEM subject key is post-quantum, the issuer signature binding it to this name is classical",
            (true, true) => "post-quantum ML-KEM key under a post-quantum issuer signature: CMS key establishment only, no change to TLS key exchange",
            _ => SignatureKeyPathNote(subjectPqc, issuerPqc)
        };
        if (pathNote is not null)
            lines.Add(Line("note", pathNote));

        if (keyAlgorithm?.StartsWith("HYBRID-", StringComparison.Ordinal) == true)
            lines.Add(Line("note", PairedIssuanceScopeNote));
        if (IsPair(keyAlgorithm))
            lines.Add(Line("note", PairScopeNote));
        if (IsComposite(keyAlgorithm))
            lines.Add(Line("note", CompositeScopeNote));
        if (IsKem(leg))
            lines.Add(Line("note", KemScopeNote));

        return lines;
    }

    private static string? SignatureKeyPathNote(bool subjectPqc, bool issuerPqc) =>
        (subjectPqc, issuerPqc) switch
        {
            (true, false) => "not a fully post-quantum certification path: the subject key is post-quantum, the issuer signature is classical",
            (false, true) => "not a fully post-quantum certification path: the issuer signature is post-quantum, the subject key is classical",
            (true, true) => "post-quantum certification path, for authentication only: no post-quantum key exchange, and no change to the TLS transport",
            (false, false) => null
        };

    private static string IssuerSignatureLabel(string? oid, string? friendlyName)
    {
        if (oid is not null && PostQuantumSignatureOids.TryGetValue(oid, out var canonical))
            return canonical;
        if (!string.IsNullOrWhiteSpace(friendlyName))
            return friendlyName;
        return string.IsNullOrWhiteSpace(oid) ? Unknown : oid;
    }

    private static string Line(string label, string value) => $"{label,-18}{value}";
}
