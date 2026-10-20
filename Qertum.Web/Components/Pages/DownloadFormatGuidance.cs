namespace Qertum.Web.Components.Pages;

/// <summary>
/// One-line explanations of the certificate download formats, phrased by what the operator is
/// installing into rather than by what the acronym expands to.
/// </summary>
/// <remarks>
/// Only PKCS#12 carries the private key. The other three are public-certificate formats, and the
/// wording keeps that distinction visible: an operator who believes a <c>.p7b</c> contains a key
/// handles it far more cautiously than it needs, and one who believes a <c>.pfx</c> does not will
/// hand out a key.
/// </remarks>
public static class DownloadFormatGuidance
{
    /// <summary>Formats the certificate detail page offers, in menu order.</summary>
    public static IReadOnlyList<string> AllFormats { get; } = ["pem", "der", "p7b", "pfx"];

    /// <summary>
    /// Shown beside PKCS#12 for a PQC-only (ML-DSA or SLH-DSA) certificate. The file follows the
    /// standards — RFC 7292 around a key encoded per RFC 9881 or RFC 9909 — so it is offered; what
    /// varies is which tools import it, and the note names only importers that were tested
    /// (2026-09-22). It replaced a note saying PKCS#12 was unavailable for these keys, which stopped
    /// being true once <c>Pkcs12Writer</c> could build the file.
    /// </summary>
    public const string PqcPkcs12Note =
        "This file carries the ML-DSA or SLH-DSA private key in its standard encoding (RFC 9881, RFC 9909). "
        + "OpenSSL 3.6 imports it; .NET on macOS does not. If your target cannot, download the certificate and "
        + "private key as separate PEM files.";

    /// <summary>
    /// Shown beside PKCS#12 for an ML-KEM certificate. Its own note rather than
    /// <see cref="PqcPkcs12Note"/>, because the importers differ and that note cites the ML-DSA and
    /// SLH-DSA RFCs. Names only what the interop run tested (2026-09-23): OpenSSL
    /// 3.6.4 and BouncyCastle Java 1.86 read the key out of Qertum's file, and .NET 10 on macOS
    /// rejects the ML-KEM OID.
    /// </summary>
    public const string KemPkcs12Note =
        "This file carries the ML-KEM private key in its standard PKCS#8 encoding. OpenSSL 3.6 and BouncyCastle "
        + "Java 1.86 import it; .NET on macOS does not. If your target cannot, download the certificate and private "
        + "key as separate PEM files.";

    /// <summary>
    /// Shown beside PKCS#12 for a composite ML-DSA certificate. The file is valid and carries the
    /// key, but none of the tools it was tested with (2026-09-22) can import a composite key from it;
    /// without this an operator exports it and blames the file.
    /// </summary>
    public const string CompositePkcs12Note =
        "This file carries the composite ML-DSA private key, but .NET on macOS and OpenSSL 3.6 cannot import "
        + "a composite key from PKCS#12 — only composite-aware software can. For most targets, download the "
        + "certificate and private key as separate PEM files.";

    /// <summary>
    /// Shown in the download menu of a paired-issuance request. Every format here carries the
    /// classical certificate, so without this an operator downloads a <c>.pfx</c>, believes they
    /// have the whole bundle and deploys half of it.
    /// </summary>
    public const string PairedIssuanceNote =
        "This request issued a paired classical + PQC bundle. These formats carry the classical "
        + "certificate; download the ML-DSA certificate and key from the PQC card below.";

    /// <summary>Shown in a signing + encryption pair's download menu: what the menu's formats hold.</summary>
    public const string PairDownloadNote =
        "A signing and encryption pair is two independent certificates, one per file. This menu downloads the "
        + "signing (ML-DSA) certificate; the encryption (ML-KEM) certificate has its own downloads below.";

    /// <summary>Guidance for one format.</summary>
    /// <param name="format">Format key: <c>pem</c>, <c>der</c>, <c>p7b</c> or <c>pfx</c>.</param>
    /// <returns>A single sentence, or an empty string for a format with no guidance.</returns>
    public static string For(string format) => format switch
    {
        "pem" => "Base64 text, the usual choice for nginx, Apache, HAProxy and most Linux services. "
               + "Include the CA chain if the server sends one to clients.",
        "der" => "Binary, and a single certificate only — no chain. Used by Java keytool imports and "
               + "some appliances that reject text formats.",
        "p7b" => "Certificate chain in one file, and nothing else. Use it to hand someone the issuing "
               + "chain, or to import a chain into Windows; it cannot be used to serve TLS on its own.",
        "pfx" => "One password-protected file holding the certificate, its chain and the private key. "
               + "This is what Windows, IIS and Java keystores import, and what you need when the "
               + "target cannot read separate files.",
        _ => string.Empty
    };
}
