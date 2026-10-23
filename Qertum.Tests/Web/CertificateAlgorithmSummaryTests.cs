using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Web.Components.Pages;
using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Web;

/// <summary>
/// The certificate detail page reports the subject public key algorithm and the issuer signature
/// algorithm as two separate facts. Before this they were one field labelled "Signature Algorithm",
/// so an ML-DSA leaf issued by the RSA CA read as <c>sha256RSA</c> and an operator concluded the
/// certificate was RSA — a certificate misread as an algorithm it does not have.
/// </summary>
public sealed class CertificateAlgorithmSummaryTests
{
    [Theory]
    [InlineData(CertificateKeyAlgorithm.Rsa, "RSA")]
    [InlineData(CertificateKeyAlgorithm.EcdsaP384, "ECDSA-P384")]
    [InlineData(CertificateKeyAlgorithm.MlDsa44, "ML-DSA-44")]
    [InlineData(CertificateKeyAlgorithm.SlhDsaSha2128f, "SLH-DSA-SHA2-128F")]
    public void SubjectKeyLabel_IsTheCanonicalNameOfTheStoredAlgorithm(
        CertificateKeyAlgorithm algorithm, string expected)
    {
        Assert.Equal(expected, CertificateAlgorithmSummary.SubjectKeyLabel(algorithm, pqcLeg: false));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, "ECDSA-P256", "ML-DSA-65")]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP384, "ECDSA-P384", "ML-DSA-87")]
    public void SubjectKeyLabel_ResolvesAHybridRequestToTheLegBeingShown(
        CertificateKeyAlgorithm algorithm, string classicalLeg, string pqcLeg)
    {
        // Paired issuance writes two certificates. Labelling either card "HYBRID-ECDSA-P256" would
        // name a key neither certificate holds.
        Assert.Equal(classicalLeg, CertificateAlgorithmSummary.SubjectKeyLabel(algorithm, pqcLeg: false));
        Assert.Equal(pqcLeg, CertificateAlgorithmSummary.SubjectKeyLabel(algorithm, pqcLeg: true));
    }

    [Fact]
    public void PairedIssuanceScopeNote_DisclaimsCompositeAndHybridTlsAuthentication()
    {
        var note = CertificateAlgorithmSummary.PairedIssuanceScopeNote;

        Assert.Contains("not a composite certificate", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("does not provide hybrid TLS authentication", note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void SubjectKeyLabel_SaysUnknownRatherThanGuessingForARowWithNoStoredAlgorithm()
    {
        // KeyAlgorithm is nullable on CertificateRequest. Defaulting to RSA here is the same
        // mistake the `?? Rsa` ban in the CSR path exists to prevent.
        Assert.Equal("Unknown", CertificateAlgorithmSummary.SubjectKeyLabel(null, pqcLeg: false));
    }

    [Theory]
    [InlineData("ML-DSA-44")]
    [InlineData("ML-DSA-65")]
    [InlineData("ML-DSA-87")]
    [InlineData("SLH-DSA-SHA2-128S")]
    [InlineData("SLH-DSA-SHA2-128F")]
    [InlineData("SLH-DSA-SHA2-192S")]
    [InlineData("SLH-DSA-SHA2-192F")]
    [InlineData("SLH-DSA-SHA2-256S")]
    [InlineData("SLH-DSA-SHA2-256F")]
    public void IssuerSignatureLabel_NamesThePqcAlgorithmARealCertificateWasSignedWith(string canonical)
    {
        var (oid, friendlyName) = SignatureAlgorithmOfALeafIssuedBy(canonical);

        Assert.Equal(canonical, CertificateAlgorithmSummary.IssuerSignatureLabel(oid, friendlyName));
    }

    [Fact]
    public void IssuerSignatureLabel_NamesRsaForALeafIssuedByTheRsaCa()
    {
        var (oid, friendlyName) = SignatureAlgorithmOfALeafIssuedBy("RSA");

        Assert.Contains("RSA", CertificateAlgorithmSummary.IssuerSignatureLabel(oid, friendlyName),
            StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IssuerSignatureLabel_FallsBackToTheRawOidRatherThanShowingNothing()
    {
        // An unrecognized signature OID is still a fact worth printing; a blank field reads as a
        // parse failure and tells the operator nothing they can look up.
        Assert.Equal("1.2.3.4.5", CertificateAlgorithmSummary.IssuerSignatureLabel("1.2.3.4.5", friendlyName: null));
        Assert.Equal("1.2.3.4.5", CertificateAlgorithmSummary.IssuerSignatureLabel("1.2.3.4.5", friendlyName: ""));
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.MlDsa65, false, true)]
    [InlineData(CertificateKeyAlgorithm.SlhDsaSha2128s, false, true)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, true, true)]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256, false, false)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP256, false, false)]
    [InlineData(CertificateKeyAlgorithm.Rsa, false, false)]
    public void SubjectIsPostQuantum_IsDecidedPerLegNotPerRequest(
        CertificateKeyAlgorithm algorithm, bool pqcLeg, bool expected)
    {
        Assert.Equal(expected, CertificateAlgorithmSummary.SubjectIsPostQuantum(algorithm, pqcLeg));
    }

    [Fact]
    public void PathNote_SaysAPqcKeyUnderAClassicalIssuerIsNotAFullyPostQuantumPath()
    {
        var note = CertificateAlgorithmSummary.CertificationPathNote(
            subjectIsPostQuantum: true, issuerIsPostQuantum: false);

        Assert.Contains("not", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("post-quantum", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("issuer", note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PathNote_SaysAClassicalKeyUnderAPqcIssuerIsStillNotAFullyPostQuantumPath()
    {
        // A post-quantum issuer signature does not make a classical subject key post-quantum.
        var note = CertificateAlgorithmSummary.CertificationPathNote(
            subjectIsPostQuantum: false, issuerIsPostQuantum: true);

        Assert.Contains("not", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("subject", note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PathNote_NeverClaimsPostQuantumKeyExchangeOrTlsAuthentication()
    {
        // PqcOnlyEnabled does not upgrade TLS transport or key exchange, and a certificate cannot.
        var note = CertificateAlgorithmSummary.CertificationPathNote(
            subjectIsPostQuantum: true, issuerIsPostQuantum: true);

        Assert.Contains("key exchange", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("not", note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PathNote_IsEmptyWhenBothHalvesAreClassicalAndThereIsNothingToExplain()
    {
        Assert.Equal(string.Empty, CertificateAlgorithmSummary.CertificationPathNote(
            subjectIsPostQuantum: false, issuerIsPostQuantum: false));
    }

    [Theory]
    [InlineData("ML-DSA-65")]
    [InlineData("SLH-DSA-SHA2-128F")]
    [InlineData("HYBRID-ECDSA-P256")]
    public void EnrollmentNote_WarnsThatAClassicalIssuerWillSignThePostQuantumCertificate(string selected)
    {
        // Choosing a post-quantum algorithm is the moment the misunderstanding forms: the requester
        // believes they are getting a post-quantum certificate, and the issuer is still RSA.
        var note = CertificateAlgorithmSummary.EnrollmentPathNote(selected, caAlgorithm: "RSA");

        Assert.Contains("not fully post-quantum", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RSA", note, StringComparison.Ordinal);
    }

    [Fact]
    public void EnrollmentNote_SaysAPostQuantumIssuerCoversAuthenticationOnly()
    {
        var note = CertificateAlgorithmSummary.EnrollmentPathNote("ML-DSA-65", caAlgorithm: "ML-DSA-87");

        Assert.Contains("ML-DSA-87", note, StringComparison.Ordinal);
        Assert.Contains("key exchange", note, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EnrollmentNote_IsEmptyForAClassicalChoiceUnderAClassicalIssuer()
    {
        Assert.Equal(string.Empty, CertificateAlgorithmSummary.EnrollmentPathNote("ECDSA-P256", caAlgorithm: "RSA"));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Ed25519")]
    public void EnrollmentNote_SaysNothingWhenTheIssuerAlgorithmIsNotKnown(string? caAlgorithm)
    {
        // CaStatusResponse.Algorithm is null for a CA key Qertum has no enum value for. Guessing
        // "classical" there would print a claim about an issuer nobody identified.
        Assert.Equal(string.Empty, CertificateAlgorithmSummary.EnrollmentPathNote("ML-DSA-65", caAlgorithm));
    }

    /// <summary>
    /// Issues a real leaf under a CA of the given algorithm and returns the leaf's signature
    /// algorithm OID and .NET friendly name. The OID table is only correct if it matches what the
    /// generator actually writes, so it is read from an issued certificate rather than asserted
    /// against a constant copied from a specification.
    /// </summary>
    private static (string Oid, string? FriendlyName) SignatureAlgorithmOfALeafIssuedBy(string caAlgorithm)
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

            var issued = generator.GenerateCertificate(
                new CertificateRequest { CommonName = "leaf.contoso.local", Type = "WebServer" },
                new CaSettings { PqcStage = PqcStage.Off, OrganizationName = "Test Org" });

            using var reader = new StringReader(issued.CertificatePem);
            var bcCert = (Org.BouncyCastle.X509.X509Certificate)
                new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();

            var oid = bcCert.SigAlgOid;
            var friendlyName = new System.Security.Cryptography.Oid(oid).FriendlyName;
            return (oid, friendlyName);
        }
        finally
        {
            if (Directory.Exists(caDir))
                try { Directory.Delete(caDir, recursive: true); } catch { /* best effort */ }
        }
    }

    // The request badge used to fall through to "Classical · RSA" for any family it did not list,
    // which would have shown every composite request as RSA.
    [Fact]
    public void FamilyLabel_NamesEveryAlgorithmsOwnFamily()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>())
        {
            var label = CertificateAlgorithmSummary.FamilyLabel(algorithm);
            var badge = CertificateAlgorithmSummary.FamilyBadgeClass(algorithm);
            var expected = algorithm.GetFamily() switch
            {
                AlgorithmFamily.Rsa => ("Classical · RSA", "algorithm-badge-rsa"),
                AlgorithmFamily.Ecdsa => ("Classical · ECDSA", "algorithm-badge-ecdsa"),
                AlgorithmFamily.Pqc => ("Full PQC · " + CertificateAlgorithmSummary.PqcSchemeName(algorithm), "algorithm-badge-pqc"),
                AlgorithmFamily.Hybrid => ("Hybrid · Classical + PQC", "algorithm-badge-hybrid"),
                AlgorithmFamily.Composite => ("Composite · ML-DSA + classical", "algorithm-badge-composite"),
                AlgorithmFamily.Kem => ("Full PQC · ML-KEM (encryption)", "algorithm-badge-kem"),
                AlgorithmFamily.Pair => ("Pair · Signing + Encryption", "algorithm-badge-pair"),
                var family => throw new InvalidOperationException($"No expectation for {family}.")
            };
            Assert.Equal(expected, (label, badge));
        }
    }

    [Fact]
    public void Composite_IsPostQuantumAsSubjectAndAsIssuer()
    {
        Assert.True(CertificateAlgorithmSummary.SubjectIsPostQuantum(CertificateKeyAlgorithm.MlDsa65EcdsaP256Sha512, pqcLeg: false));
        Assert.Equal("MLDSA65-ECDSA-P256-SHA512", CertificateAlgorithmSummary.IssuerSignatureLabel("1.3.6.1.5.5.7.6.45", friendlyName: null));
        Assert.True(CertificateAlgorithmSummary.IssuerIsPostQuantum("1.3.6.1.5.5.7.6.45"));
        Assert.Contains("post-quantum end to end",
            CertificateAlgorithmSummary.EnrollmentPathNote("MLDSA65-ECDSA-P256-SHA512", "MLDSA87-ECDSA-P384-SHA512"),
            StringComparison.Ordinal);
    }

    // What an ML-KEM certificate is for, and what it cannot do: every claim the note makes must be
    // one the interop run measured (CMS), and none may reach TLS.
    [Fact]
    public void KemScopeNote_SaysWhatTheKeyIsForAndThatItCannotSignOrDoTls()
    {
        var note = CertificateAlgorithmSummary.KemScopeNote;

        Assert.Contains("encrypt to its holder", note, StringComparison.Ordinal);
        Assert.Contains("RFC 9629", note, StringComparison.Ordinal);
        Assert.Contains("cannot sign", note, StringComparison.Ordinal);
        Assert.Contains("cannot authenticate a TLS client or server", note, StringComparison.Ordinal);
        Assert.Contains("OpenSSL 3.6", note, StringComparison.Ordinal);
        Assert.Contains("BouncyCastle Java 1.86", note, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("RSA", false)]
    [InlineData("ECDSA-P256", false)]
    [InlineData("ML-DSA-65", true)]
    [InlineData("MLDSA87-ECDSA-P384-SHA512", true)]
    public void EnrollmentPathNote_ForMlKem_SeparatesTheKeyFromTheSignatureBindingIt(string caAlgorithm, bool issuerIsPostQuantum)
    {
        var note = CertificateAlgorithmSummary.EnrollmentPathNote("ML-KEM-768", caAlgorithm);

        Assert.Contains($"This CA signs with {caAlgorithm}", note, StringComparison.Ordinal);
        Assert.Contains("ML-KEM key", note, StringComparison.Ordinal);
        Assert.DoesNotContain("authentication only", note, StringComparison.Ordinal);
        if (issuerIsPostQuantum)
            Assert.Contains("does not change TLS key exchange", note, StringComparison.Ordinal);
        else
            Assert.Contains("is not", note, StringComparison.Ordinal);
    }

    [Fact]
    public void CertificationPathNote_WithoutTheKemFlag_IsUnchanged()
    {
        Assert.Contains("authentication only", CertificateAlgorithmSummary.CertificationPathNote(true, true), StringComparison.Ordinal);
        Assert.Equal(string.Empty, CertificateAlgorithmSummary.CertificationPathNote(false, false, subjectIsKem: false));
    }

    // Derived from the enum, so a new PQC-only parameter set that is not given a scheme fails here
    // instead of rendering a badge with a blank name.
    [Fact]
    public void PqcSchemeName_NamesTheSchemeOfEveryPqcOnlyAlgorithm()
    {
        foreach (var algorithm in Enum.GetValues<CertificateKeyAlgorithm>())
        {
            var scheme = CertificateAlgorithmSummary.PqcSchemeName(algorithm);
            if (algorithm.GetFamily() is AlgorithmFamily.Pqc or AlgorithmFamily.Kem)
            {
                Assert.NotNull(scheme);
                Assert.StartsWith(scheme + "-", algorithm.ToCanonicalString(), StringComparison.Ordinal);
            }
            else
            {
                Assert.Null(scheme);
            }
        }
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa44MlKem512, "ML-DSA-44", "ML-KEM-512")]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa65MlKem768, "ML-DSA-65", "ML-KEM-768")]
    [InlineData(CertificateKeyAlgorithm.PairMlDsa87MlKem1024, "ML-DSA-87", "ML-KEM-1024")]
    public void APair_LabelsEachCertificateWithItsOwnKey_AndBothAreInPostQuantum(
        CertificateKeyAlgorithm algorithm, string signing, string encryption)
    {
        Assert.Equal(signing, CertificateAlgorithmSummary.SubjectKeyLabel(algorithm, pqcLeg: false));
        Assert.Equal(encryption, CertificateAlgorithmSummary.SubjectKeyLabel(algorithm, pqcLeg: true));
        // Unlike a hybrid pair, neither certificate of this one is classical.
        Assert.True(CertificateAlgorithmSummary.SubjectIsPostQuantum(algorithm, pqcLeg: false));
        Assert.True(CertificateAlgorithmSummary.SubjectIsPostQuantum(algorithm, pqcLeg: true));
    }

    [Fact]
    public void APairChoice_RaisesThePostQuantumPathQuestion_LikeAStraightPqcChoice()
    {
        Assert.Equal(
            CertificateAlgorithmSummary.EnrollmentPathNote("ML-DSA-65", "RSA"),
            CertificateAlgorithmSummary.EnrollmentPathNote("PAIR-ML-DSA-65-ML-KEM-768", "RSA"));
    }

    [Fact]
    public void PairScopeNote_SaysTwoIndependentCertificates_AndWhatTheEncryptionOneCannotDo()
    {
        var note = CertificateAlgorithmSummary.PairScopeNote;

        Assert.Contains("two independent certificates", note, StringComparison.Ordinal);
        Assert.Contains("not a composite", note, StringComparison.Ordinal);
        Assert.Contains("cannot sign", note, StringComparison.Ordinal);
        Assert.Contains("TLS", note, StringComparison.Ordinal);
    }
}
