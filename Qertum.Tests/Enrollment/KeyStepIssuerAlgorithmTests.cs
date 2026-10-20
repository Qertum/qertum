using Bunit;
using Qertum.Web.Components.Pages.Enrollment;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// Choosing a post-quantum algorithm is where the misunderstanding forms: the requester believes
/// they are getting a post-quantum certificate, while the CA that will sign it is still classical.
/// The key step says so at the point of choice rather than leaving it to be discovered on the
/// issued certificate.
/// </summary>
public sealed class KeyStepIssuerAlgorithmTests
{
    [Fact]
    public async Task ChoosingPqcUnderAClassicalCa_SaysThePathWillNotBeFullyPostQuantum()
    {
        await using var context = new BunitContext();
        var draft = new EnrollmentDraft { KeyAlgorithm = "ML-DSA-65", PilotPqc = true };

        var cut = context.Render<KeyStep>(p => p
            .Add(x => x.Draft, draft)
            .Add(x => x.CaAlgorithm, "RSA"));

        var note = cut.Find("[data-test='enrollment-path-note']").TextContent;
        Assert.Contains("not fully post-quantum", note, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("RSA", note, StringComparison.Ordinal);
    }

    [Fact]
    public async Task ChoosingAClassicalAlgorithmUnderAClassicalCa_ShowsNoNote()
    {
        await using var context = new BunitContext();
        var draft = new EnrollmentDraft { KeyAlgorithm = "ECDSA-P256" };

        var cut = context.Render<KeyStep>(p => p
            .Add(x => x.Draft, draft)
            .Add(x => x.CaAlgorithm, "RSA"));

        Assert.Empty(cut.FindAll("[data-test='enrollment-path-note']"));
    }

    [Fact]
    public async Task AnUnknownCaAlgorithm_ShowsNoNoteRatherThanGuessing()
    {
        await using var context = new BunitContext();
        var draft = new EnrollmentDraft { KeyAlgorithm = "ML-DSA-65", PilotPqc = true };

        var cut = context.Render<KeyStep>(p => p
            .Add(x => x.Draft, draft)
            .Add(x => x.CaAlgorithm, null));

        Assert.Empty(cut.FindAll("[data-test='enrollment-path-note']"));
    }

    [Theory]
    [InlineData("HYBRID-ECDSA-P256")]
    [InlineData("HYBRID-ECDSA-P384")]
    public async Task ChoosingAPairedAlgorithm_SaysThePairIsNeitherCompositeNorHybridTls(string algorithm)
    {
        await using var context = new BunitContext();
        var draft = new EnrollmentDraft { KeyAlgorithm = algorithm, PilotPqc = true };

        var cut = context.Render<KeyStep>(p => p
            .Add(x => x.Draft, draft)
            .Add(x => x.CaAlgorithm, "RSA"));

        Assert.Equal(
            Qertum.Web.Components.Pages.CertificateAlgorithmSummary.PairedIssuanceScopeNote,
            cut.Find("[data-test='paired-scope-note']").TextContent.Trim());
    }

    [Theory]
    [InlineData("ML-DSA-65")]
    [InlineData("ECDSA-P256")]
    public async Task ChoosingASingleAlgorithm_ShowsNoPairedScopeNote(string algorithm)
    {
        await using var context = new BunitContext();
        var draft = new EnrollmentDraft { KeyAlgorithm = algorithm, PilotPqc = true };

        var cut = context.Render<KeyStep>(p => p
            .Add(x => x.Draft, draft)
            .Add(x => x.CaAlgorithm, "RSA"));

        Assert.Empty(cut.FindAll("[data-test='paired-scope-note']"));
    }
}
