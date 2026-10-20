using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Cli.Commands;
using Qertum.Services;
using Qertum.Web.Components.Pages;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Cli;

/// <summary>
/// <c>qca cert download-cert</c> reports the subject key algorithm and the issuer signature
/// algorithm as two facts, the same split the Web detail page makes. The CLI takes no project
/// reference, so it carries its own copy of the labels; the contract tests here pin that copy to
/// <see cref="CertificateAlgorithmSummary"/> so the two surfaces cannot drift.
/// </summary>
public sealed class CertificateAlgorithmLinesTests
{
    [Fact]
    public void PostQuantumSignatureOidTable_MatchesTheWebTable()
    {
        foreach (var (oid, name) in CertificateAlgorithmLines.PostQuantumSignatureOids)
            Assert.Equal(CertificateAlgorithmSummary.IssuerSignatureLabel(oid, friendlyName: null), name);

        // Every PQC or composite algorithm the server can sign with must be named, or the CLI prints a bare OID.
        var pqcAlgorithms = Enum.GetValues<CertificateKeyAlgorithm>()
            .Where(a => a.GetFamily() is AlgorithmFamily.Pqc or AlgorithmFamily.Composite)
            .Select(a => a.ToCanonicalString())
            .Order(StringComparer.Ordinal);
        Assert.Equal(pqcAlgorithms, CertificateAlgorithmLines.PostQuantumSignatureOids.Values.Order(StringComparer.Ordinal));
    }

    [Fact]
    public void CompositeNotes_AreTheWebsCopiesWordForWord()
    {
        Assert.Equal(CertificateAlgorithmSummary.CompositeScopeNote, CertificateAlgorithmLines.CompositeScopeNote);
        Assert.Equal(Qertum.Web.Components.Pages.DownloadFormatGuidance.CompositePkcs12Note, CertificateAlgorithmLines.CompositePkcs12Note);
        Assert.Equal(Qertum.Web.Components.Pages.DownloadFormatGuidance.PqcPkcs12Note, CertificateAlgorithmLines.PqcPkcs12Note);
    }

    [Fact]
    public void IsComposite_MatchesTheCompositeFamilyForEveryAlgorithm()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>())
            Assert.Equal(algorithm.GetFamily() == AlgorithmFamily.Composite, CertificateAlgorithmLines.IsComposite(algorithm.ToCanonicalString()));
    }

    [Fact]
    public void SubjectKeyLabelAndPostQuantumFlag_MatchTheWebForEveryAlgorithmAndLeg()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>())
        foreach (var pqcLeg in new[] { false, true })
        {
            var canonical = algorithm.ToCanonicalString();
            Assert.Equal(
                CertificateAlgorithmSummary.SubjectKeyLabel(algorithm, pqcLeg),
                CertificateAlgorithmLines.SubjectKeyLabel(canonical, pqcLeg));
            Assert.Equal(
                CertificateAlgorithmSummary.SubjectIsPostQuantum(algorithm, pqcLeg),
                CertificateAlgorithmLines.SubjectIsPostQuantum(canonical, pqcLeg));
        }
    }

    [Fact]
    public void PairedIssuanceScopeNote_IsTheWebWording()
    {
        Assert.Equal(CertificateAlgorithmSummary.PairedIssuanceScopeNote, CertificateAlgorithmLines.PairedIssuanceScopeNote);
    }

    [Fact]
    public void ARowWithNoStoredAlgorithm_IsUnknownRatherThanRsa()
    {
        // `cert list` used to print `KeyAlgorithm ?? "RSA"` — the same guess the `?? Rsa` ban on
        // the CSR path exists to prevent.
        Assert.Equal("Unknown", CertificateAlgorithmLines.SubjectKeyLabel(null, pqcLeg: false));
    }

    [Fact]
    public void PqcLeafUnderAClassicalCa_NamesBothAlgorithmsAndSaysThePathIsNotFullyPostQuantum()
    {
        var pem = IssueLeaf(caAlgorithm: "RSA", leafAlgorithm: CertificateKeyAlgorithm.MlDsa65).CertificatePem;

        var lines = CertificateAlgorithmLines.Describe("ML-DSA-65", pqcLeg: false, pem);

        Assert.Contains(lines, l => l.StartsWith("subject key") && l.EndsWith("ML-DSA-65"));
        Assert.Contains(lines, l => l.StartsWith("issuer signature") && l.Contains("RSA", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(lines, l => l.StartsWith("note") && l.Contains("not a fully post-quantum", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void LeafUnderAPqcCa_NamesTheIssuerAlgorithmRatherThanABareOid()
    {
        var pem = IssueLeaf(caAlgorithm: "ML-DSA-44", leafAlgorithm: CertificateKeyAlgorithm.MlDsa44).CertificatePem;

        var lines = CertificateAlgorithmLines.Describe("ML-DSA-44", pqcLeg: false, pem);

        Assert.Contains(lines, l => l.StartsWith("issuer signature") && l.EndsWith("ML-DSA-44"));
        // End to end post-quantum still covers authentication only.
        Assert.Contains(lines, l => l.StartsWith("note") && l.Contains("key exchange", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CompositeLeafUnderACompositeCa_NamesBothAndCarriesTheCompositeScopeNote()
    {
        var pem = IssueLeaf(caAlgorithm: "MLDSA87-ECDSA-P384-SHA512", leafAlgorithm: CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512).CertificatePem;

        var lines = CertificateAlgorithmLines.Describe("MLDSA65-ECDSA-P256-SHA512", pqcLeg: false, pem);

        Assert.Contains(lines, l => l.StartsWith("subject key") && l.EndsWith("MLDSA65-ECDSA-P256-SHA512"));
        Assert.Contains(lines, l => l.StartsWith("issuer signature") && l.EndsWith("MLDSA87-ECDSA-P384-SHA512"));
        Assert.Contains(lines, l => l.StartsWith("note") && l.EndsWith(CertificateAlgorithmLines.CompositeScopeNote));
    }

    [Fact]
    public void KemPkcs12Note_IsTheWebsCopyWordForWord() =>
        Assert.Equal(Qertum.Web.Components.Pages.DownloadFormatGuidance.KemPkcs12Note, CertificateAlgorithmLines.KemPkcs12Note);

    // What download-cert -F pfx prints to stderr before the file: one note per key kind, or none.
    [Theory]
    [InlineData("ML-KEM-768", false, "note: ", nameof(CertificateAlgorithmLines.KemPkcs12Note))]
    [InlineData("ML-DSA-65", false, "note: ", nameof(CertificateAlgorithmLines.PqcPkcs12Note))]
    [InlineData("SLH-DSA-SHA2-128F", false, "note: ", nameof(CertificateAlgorithmLines.PqcPkcs12Note))]
    [InlineData("HYBRID-ECDSA-P256", true, "note: ", nameof(CertificateAlgorithmLines.PqcPkcs12Note))]
    [InlineData("MLDSA65-ECDSA-P256-SHA512", false, "warning: ", nameof(CertificateAlgorithmLines.CompositePkcs12Note))]
    public void Pkcs12Note_NamesTheNoteForTheKeyBeingExported(string algorithm, bool pqcLeg, string prefix, string noteName)
    {
        var expected = noteName switch
        {
            nameof(CertificateAlgorithmLines.KemPkcs12Note) => CertificateAlgorithmLines.KemPkcs12Note,
            nameof(CertificateAlgorithmLines.PqcPkcs12Note) => CertificateAlgorithmLines.PqcPkcs12Note,
            _ => CertificateAlgorithmLines.CompositePkcs12Note
        };

        Assert.Equal(prefix + expected, CertificateAlgorithmLines.Pkcs12Note(algorithm, pqcLeg));
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECDSA-P256")]
    [InlineData("HYBRID-ECDSA-P256")]
    [InlineData(null)]
    public void Pkcs12Note_IsNullForAClassicalKey(string? algorithm) =>
        Assert.Null(CertificateAlgorithmLines.Pkcs12Note(algorithm, pqcLeg: false));

    [Fact]
    public void KemScopeNote_IsTheWebsCopyWordForWord() =>
        Assert.Equal(CertificateAlgorithmSummary.KemScopeNote, CertificateAlgorithmLines.KemScopeNote);

    [Theory]
    [InlineData("RSA", "classical")]
    [InlineData("ML-DSA-65", "CMS key establishment only")]
    public void MlKemLeaf_CarriesTheKemScopeNoteAndAKemPathNote(string caAlgorithm, string expectedInPathNote)
    {
        var pem = IssueLeaf(caAlgorithm, leafAlgorithm: CertificateKeyAlgorithm.MlKem768).CertificatePem;

        var lines = CertificateAlgorithmLines.Describe("ML-KEM-768", pqcLeg: false, pem);

        Assert.Contains(lines, l => l.StartsWith("subject key") && l.EndsWith("ML-KEM-768"));
        Assert.Contains(lines, l => l.StartsWith("note") && l.EndsWith(CertificateAlgorithmLines.KemScopeNote));
        Assert.Contains(lines, l => l.StartsWith("note") && l.Contains("ML-KEM") && l.Contains(expectedInPathNote));
        Assert.DoesNotContain(lines, l => l.Contains("for authentication only"));
    }

    [Fact]
    public void IsKem_MatchesTheKemFamilyForEveryAlgorithm()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>())
            Assert.Equal(algorithm.GetFamily() == AlgorithmFamily.Kem, CertificateAlgorithmLines.IsKem(algorithm.ToCanonicalString()));
    }

    [Fact]
    public void ClassicalLeafUnderAClassicalCa_HasNoNote()
    {
        var pem = IssueLeaf(caAlgorithm: "RSA", leafAlgorithm: CertificateKeyAlgorithm.EcdsaP256).CertificatePem;

        var lines = CertificateAlgorithmLines.Describe("ECDSA-P256", pqcLeg: false, pem);

        Assert.Equal(2, lines.Count);
        Assert.DoesNotContain(lines, l => l.StartsWith("note"));
    }

    [Fact]
    public void EitherLegOfAPair_CarriesThePairedScopeNote()
    {
        var issued = IssueLeaf(caAlgorithm: "RSA", leafAlgorithm: CertificateKeyAlgorithm.HybridEcdsaP256);

        var classical = CertificateAlgorithmLines.Describe("HYBRID-ECDSA-P256", pqcLeg: false, issued.CertificatePem);
        var pqc = CertificateAlgorithmLines.Describe("HYBRID-ECDSA-P256", pqcLeg: true, issued.PqcCertificatePem!);

        Assert.Contains(classical, l => l.StartsWith("subject key") && l.EndsWith("ECDSA-P256"));
        Assert.Contains(pqc, l => l.StartsWith("subject key") && l.EndsWith("ML-DSA-65"));
        Assert.Contains(classical, l => l.Contains(CertificateAlgorithmLines.PairedIssuanceScopeNote));
        Assert.Contains(pqc, l => l.Contains(CertificateAlgorithmLines.PairedIssuanceScopeNote));
    }

    [Fact]
    public void AnUnparseablePem_ReportsTheIssuerAsUnknown()
    {
        var lines = CertificateAlgorithmLines.Describe("RSA", pqcLeg: false, "not a certificate");

        Assert.Contains(lines, l => l.StartsWith("issuer signature") && l.EndsWith("Unknown"));
    }

    [Fact]
    public void PairScopeNote_IsTheWebsCopyWordForWord() =>
        Assert.Equal(CertificateAlgorithmSummary.PairScopeNote, CertificateAlgorithmLines.PairScopeNote);

    [Theory]
    [InlineData("PAIR-ML-DSA-65-ML-KEM-768", false)]
    [InlineData("PAIR-ML-DSA-65-ML-KEM-768", true)]
    public void APairsPkcs12Note_IsTheNoteOfThatCertificatesOwnKey(string algorithm, bool secondLeg)
    {
        var note = CertificateAlgorithmLines.Pkcs12Note(algorithm, secondLeg);

        Assert.Equal("note: " + (secondLeg ? CertificateAlgorithmLines.KemPkcs12Note : CertificateAlgorithmLines.PqcPkcs12Note), note);
    }

    [Fact]
    public void TheEncryptionCertificateOfAPair_IsDescribedAsAnMlKemCertificate_WithBothScopeNotes()
    {
        var pem = IssueLeaf(caAlgorithm: "RSA", leafAlgorithm: CertificateKeyAlgorithm.MlKem768).CertificatePem;

        var lines = CertificateAlgorithmLines.Describe("PAIR-ML-DSA-65-ML-KEM-768", pqcLeg: true, pem);

        Assert.Contains(lines, l => l.Contains("ML-KEM-768", StringComparison.Ordinal) && l.StartsWith("subject key"));
        Assert.Contains(lines, l => l.Contains(CertificateAlgorithmLines.KemScopeNote, StringComparison.Ordinal));
        Assert.Contains(lines, l => l.Contains(CertificateAlgorithmLines.PairScopeNote, StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains("for authentication only", StringComparison.Ordinal));
    }

    [Fact]
    public void TheSigningCertificateOfAPair_IsDescribedAsAnMlDsaCertificate_WithThePairNoteOnly()
    {
        var pem = IssueLeaf(caAlgorithm: "RSA", leafAlgorithm: CertificateKeyAlgorithm.MlDsa65).CertificatePem;

        var lines = CertificateAlgorithmLines.Describe("PAIR-ML-DSA-65-ML-KEM-768", pqcLeg: false, pem);

        Assert.Contains(lines, l => l.Contains("ML-DSA-65", StringComparison.Ordinal) && l.StartsWith("subject key"));
        Assert.Contains(lines, l => l.Contains(CertificateAlgorithmLines.PairScopeNote, StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.Contains(CertificateAlgorithmLines.KemScopeNote, StringComparison.Ordinal));
    }

    private static GeneratedCertificate IssueLeaf(string caAlgorithm, CertificateKeyAlgorithm leafAlgorithm)
    {
        var caDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));
        try
        {
            var generator = new CertificateGenerator(
                new EphemeralDataProtectionProvider(),
                new CaDataOptions { Directory = caDir },
                NullLogger<CertificateGenerator>.Instance);
            generator.GenerateCa(new GenerateCaRequest
            {
                CommonName = $"{caAlgorithm} Issuing CA",
                KeyAlgorithm = CertificateKeyAlgorithmExtensions.Parse(caAlgorithm)!.Value,
                ValidityDays = 365
            });

            return generator.GenerateCertificate(
                new CertificateRequest { CommonName = "leaf.contoso.local", Type = "WebServer", KeyAlgorithm = leafAlgorithm },
                new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }
}
