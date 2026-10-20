using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Qertum.Services;
using CertificateRequest = Qertum.Services.CertificateRequest;
using BcCertificate = Org.BouncyCastle.X509.X509Certificate;
using BcCrl = Org.BouncyCastle.X509.X509Crl;

namespace Qertum.Tests;

/// <summary>
/// Regression tests for the former IMPROVEMENTS.md audit §3.5 (issued certificates carried no Subject or Authority Key
/// Identifier) and §3.6 (the CRL had no CRL number and reported every revocation as "unspecified").
/// </summary>
public sealed class CertificateKeyIdentifierTests : IDisposable
{
    private readonly CertificateGenerator _generator;
    private readonly string _caDataDir;

    public CertificateKeyIdentifierTests()
    {
        // Isolated temp directory per instance, matching CertificateGeneratorTests: the Aspire
        // fixture writes real CA files under the test bin directory while it runs.
        _caDataDir = Path.Combine(Path.GetTempPath(), "CaData-" + Guid.NewGuid().ToString("N"));

        _generator = new CertificateGenerator(
            new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _caDataDir },
            NullLogger<CertificateGenerator>.Instance);

        _generator.GenerateCa(new GenerateCaRequest
        {
            CommonName = "Test Root CA",
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa,
            ValidityDays = 365
        });
    }

    public void Dispose()
    {
        if (Directory.Exists(_caDataDir))
            try { Directory.Delete(_caDataDir, recursive: true); } catch { /* best effort */ }
    }

    private static BcCertificate ParseBc(string pem)
    {
        using var reader = new StringReader(pem);
        return (BcCertificate)new Org.BouncyCastle.OpenSsl.PemReader(reader).ReadObject();
    }

    private BcCertificate CaCertificate() => ParseBc(_generator.GetCaCertificatePem());

    private static byte[]? SkiOf(BcCertificate cert)
    {
        var raw = cert.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
        if (raw is null) return null;

        return SubjectKeyIdentifier.GetInstance(
            Asn1Object.FromByteArray(raw.GetOctets())).GetKeyIdentifier();
    }

    private static byte[]? AkiOf(BcCertificate cert)
    {
        var raw = cert.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        if (raw is null) return null;

        // BouncyCastle 2.7.0 obsoleted GetKeyIdentifier() in favour of the property.
        return AuthorityKeyIdentifier.GetInstance(
            Asn1Object.FromByteArray(raw.GetOctets())).KeyIdentifier?.GetOctets();
    }

    private GeneratedCertificate IssueLeaf(string commonName = "leaf.contoso.local") =>
        _generator.GenerateCertificate(
            new CertificateRequest { CommonName = commonName, Type = "WebServer", PropertiesJson = "{}" },
            new CaSettings { PqcStage = PqcStage.Off });

    // ── §3.5 Subject / Authority Key Identifier ───────────────────────────────

    [Fact]
    public void RootCaCarriesASubjectKeyIdentifier()
    {
        // RFC 5280 §4.2.1.2 requires it on a CA certificate: it is the anchor every issued
        // certificate's AuthorityKeyIdentifier points back to.
        Assert.NotNull(SkiOf(CaCertificate()));
    }

    [Fact]
    public void RootCaHasNoAuthorityKeyIdentifier()
    {
        // The root is self-signed; adding an AKI would imply an issuer above it.
        Assert.Null(AkiOf(CaCertificate()));
    }

    [Fact]
    public void IssuedCertificateCarriesASubjectKeyIdentifier()
    {
        var leaf = ParseBc(IssueLeaf().CertificatePem);

        Assert.NotNull(SkiOf(leaf));
    }

    [Fact]
    public void IssuedCertificateAuthorityKeyIdentifierMatchesTheCaSubjectKeyIdentifier()
    {
        // This equality is what lets a chain builder pick the right issuer after a CA key rotation,
        // instead of falling back to matching by Distinguished Name.
        var leaf = ParseBc(IssueLeaf().CertificatePem);

        var leafAki = AkiOf(leaf);
        var caSki = SkiOf(CaCertificate());

        Assert.NotNull(leafAki);
        Assert.NotNull(caSki);
        Assert.Equal(caSki, leafAki);
    }

    [Fact]
    public void TwoCertificatesGetDifferentSubjectKeyIdentifiers()
    {
        // The identifier derives from the subject public key, so distinct keys must not collide.
        var first = SkiOf(ParseBc(IssueLeaf("first.contoso.local").CertificatePem));
        var second = SkiOf(ParseBc(IssueLeaf("second.contoso.local").CertificatePem));

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void KeyIdentifierExtensionsAreNotCritical()
    {
        // RFC 5280 requires both to be non-critical; marking them critical breaks older validators.
        var leaf = ParseBc(IssueLeaf().CertificatePem);
        var critical = leaf.GetCriticalExtensionOids();

        Assert.DoesNotContain(X509Extensions.SubjectKeyIdentifier.Id, critical.Cast<string>());
        Assert.DoesNotContain(X509Extensions.AuthorityKeyIdentifier.Id, critical.Cast<string>());
    }

    [Fact]
    public void IssuedCertificateStillChainsToTheCa()
    {
        // Guards against the added extensions breaking signature verification.
        var leaf = ParseBc(IssueLeaf().CertificatePem);

        leaf.Verify(CaCertificate().GetPublicKey());
    }

    // ── §3.6 CRL number ───────────────────────────────────────────────────────

    private static BcCrl ParseCrl(byte[] der)
    {
        using var ms = new MemoryStream(der);
        return new X509CrlParser().ReadCrl(ms);
    }

    private static Org.BouncyCastle.Math.BigInteger? CrlNumberOf(BcCrl crl)
    {
        var raw = crl.GetExtensionValue(X509Extensions.CrlNumber);
        return raw is null
            ? null
            : CrlNumber.GetInstance(Asn1Object.FromByteArray(raw.GetOctets())).PositiveValue;
    }

    [Fact]
    public void CrlCarriesTheSuppliedCrlNumber()
    {
        var crl = ParseCrl(_generator.GenerateCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 7));

        Assert.Equal(7, CrlNumberOf(crl)?.IntValue);
    }

    [Fact]
    public void SuccessiveCrlNumbersAreDistinct()
    {
        // A client caching two CRLs uses this to decide which is newer.
        var first = CrlNumberOf(ParseCrl(_generator.GenerateCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 1)));
        var second = CrlNumberOf(ParseCrl(_generator.GenerateCrl([], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 2)));

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.True(second.IntValue > first.IntValue);
    }

    // ── §3.6 revocation reason ────────────────────────────────────────────────

    private CertificateRequest RevokedLeaf(string? reason)
    {
        var issued = IssueLeaf();
        return new CertificateRequest
        {
            CommonName = "leaf.contoso.local",
            CertificatePem = issued.CertificatePem,
            RevocationReason = reason,
            RevokedAtUtc = DateTime.UtcNow
        };
    }

    private int? ReasonCodeFor(string? storedReason)
    {
        var request = RevokedLeaf(storedReason);
        var crl = ParseCrl(_generator.GenerateCrl([request], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 1));

        var leaf = ParseBc(request.CertificatePem!);
        var entry = crl.GetRevokedCertificate(leaf.SerialNumber);
        Assert.NotNull(entry);

        var raw = entry.GetExtensionValue(X509Extensions.ReasonCode);
        if (raw is null) return null;

        return ((DerEnumerated)Asn1Object.FromByteArray(raw.GetOctets())).Value.IntValue;
    }

    [Fact]
    public void SupersededReasonReachesTheCrl()
    {
        // AutoRevokeOnRenewal writes exactly this string, so it must map without operator action.
        Assert.Equal(CrlReason.Superseded, ReasonCodeFor("superseded"));
    }

    [Theory]
    [InlineData("keyCompromise")]
    [InlineData("key compromise")]
    [InlineData("key-compromise")]
    [InlineData("KEYCOMPROMISE")]
    public void ReasonMatchingToleratesSpellingVariants(string stored)
    {
        Assert.Equal(CrlReason.KeyCompromise, CertificateGenerator.MapRevocationReason(stored));
    }

    [Theory]
    [InlineData("cessationOfOperation", CrlReason.CessationOfOperation)]
    [InlineData("affiliationChanged", CrlReason.AffiliationChanged)]
    [InlineData("caCompromise", CrlReason.CACompromise)]
    [InlineData("privilegeWithdrawn", CrlReason.PrivilegeWithdrawn)]
    public void KnownReasonsMapToTheirCodes(string stored, int expected)
    {
        Assert.Equal(expected, CertificateGenerator.MapRevocationReason(stored));
    }

    [Theory]
    [InlineData("because I said so")]
    [InlineData("")]
    [InlineData(null)]
    public void UnknownReasonsFallBackToUnspecified(string? stored)
    {
        Assert.Equal(CrlReason.Unspecified, CertificateGenerator.MapRevocationReason(stored));
    }

    [Fact]
    public void FreeTextReasonStillRevokesTheCertificate()
    {
        // The entry must appear on the CRL whatever the reason text says — the certificate is revoked
        // regardless of whether the reason is recognized. The reason extension itself is absent, which
        // is what RFC 5280 §5.3.1 calls for when the reason is "unspecified": the code exists for
        // completeness, but an entry that would carry it SHOULD omit the extension instead.
        var request = RevokedLeaf("because I said so");
        var crl = ParseCrl(_generator.GenerateCrl([request], new CaSettings { PqcStage = PqcStage.Off }, crlNumber: 1));
        var leaf = ParseBc(request.CertificatePem!);

        Assert.NotNull(crl.GetRevokedCertificate(leaf.SerialNumber));
        Assert.Null(ReasonCodeFor("because I said so"));
    }
}
