using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// The one-line explanations beside each download format. An operator picking a format is choosing
/// for a target application, so the text names applications rather than restating the acronym.
/// </summary>
public sealed class DownloadFormatGuidanceTests
{
    [Fact]
    public void EveryOfferedFormatHasGuidance()
    {
        Assert.All(DownloadFormatGuidance.AllFormats,
            format => Assert.False(string.IsNullOrWhiteSpace(DownloadFormatGuidance.For(format))));
    }

    [Theory]
    [InlineData("pem", "nginx")]
    [InlineData("der", "single")]
    [InlineData("p7b", "chain")]
    [InlineData("pfx", "Windows")]
    public void GuidanceNamesWhatTheFormatIsActuallyFor(string format, string expected)
    {
        Assert.Contains(expected, DownloadFormatGuidance.For(format), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void NeitherKeylessFormatIsDescribedAsCarryingAKey()
    {
        // PEM, DER and PKCS#7 are public-certificate formats; only PKCS#12 carries the private key,
        // and implying otherwise would have an operator hand out a file expecting it to be inert.
        foreach (var format in new[] { "pem", "der", "p7b" })
            Assert.DoesNotContain("private key", DownloadFormatGuidance.For(format), StringComparison.OrdinalIgnoreCase);

        Assert.Contains("private key", DownloadFormatGuidance.For("pfx"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PqcPkcs12NoteNamesBothSchemesTheirStandardsAndWhoCannotImportThem()
    {
        // PKCS#12 is offered for ML-DSA and SLH-DSA keys because their PKCS#8 encodings follow
        // RFC 9881 and RFC 9909. Importer support is the limitation, and the note may only name
        // importers that were actually tested.
        var note = DownloadFormatGuidance.PqcPkcs12Note;
        Assert.Contains("ML-DSA", note, StringComparison.Ordinal);
        Assert.Contains("SLH-DSA", note, StringComparison.Ordinal);
        Assert.Contains("RFC 9881", note, StringComparison.Ordinal);
        Assert.Contains("RFC 9909", note, StringComparison.Ordinal);
        Assert.Contains("private key", note, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Windows", note, StringComparison.Ordinal);
    }

    [Fact]
    public void KemPkcs12NoteNamesOnlyTheImportersTheInteropRunTested()
    {
        // The interop run (2026-09-23): OpenSSL 3.6 and BouncyCastle Java 1.86 read the key out of
        // Qertum's file; .NET 10 on macOS refuses the ML-KEM OID. Windows was never tested.
        var note = DownloadFormatGuidance.KemPkcs12Note;
        Assert.Contains("ML-KEM private key", note, StringComparison.Ordinal);
        Assert.Contains("OpenSSL 3.6", note, StringComparison.Ordinal);
        Assert.Contains("BouncyCastle Java 1.86", note, StringComparison.Ordinal);
        Assert.Contains(".NET on macOS does not", note, StringComparison.Ordinal);
        Assert.Contains("PEM", note, StringComparison.Ordinal);
        Assert.DoesNotContain("Windows", note, StringComparison.Ordinal);
    }

    [Fact]
    public void CompositePkcs12NoteSaysTheKeyIsInsideButMainstreamToolsCannotImportIt()
    {
        // Both halves of the download rule hold for composite too: the .pfx carries a key. What is
        // new is that no mainstream importer can read that key, which the note must not hide.
        Assert.Contains("private key", DownloadFormatGuidance.CompositePkcs12Note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("cannot import", DownloadFormatGuidance.CompositePkcs12Note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("PEM", DownloadFormatGuidance.CompositePkcs12Note, StringComparison.Ordinal);
        // Windows was never tested; only what was measured may be claimed.
        Assert.DoesNotContain("Windows", DownloadFormatGuidance.CompositePkcs12Note, StringComparison.Ordinal);
    }

    [Fact]
    public void ExplainsThatTheseFormatsCoverOnlyTheClassicalHalfOfAPair()
    {
        // Paired issuance produces two certificates. Every format in this menu carries the
        // classical one, so an operator who downloads a .pfx here and believes they have taken the
        // whole bundle deploys half of it.
        Assert.Contains("classical", DownloadFormatGuidance.PairedIssuanceNote, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ML-DSA", DownloadFormatGuidance.PairedIssuanceNote, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnUnknownFormatYieldsNothingRatherThanThrowing()
    {
        Assert.Equal(string.Empty, DownloadFormatGuidance.For("tar"));
    }
}
