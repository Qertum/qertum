using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerCertificateFactsTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "IssuerFacts-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) try { Directory.Delete(_dir, true); } catch { /* best effort */ }
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.Rsa)]
    [InlineData(CertificateKeyAlgorithm.EcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.MlDsa65)]
    public void Read_SelfSignedRoot_ReportsItsFacts(CertificateKeyAlgorithm algorithm)
    {
        var generator = new CertificateGenerator(new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _dir }, NullLogger<CertificateGenerator>.Instance);
        generator.GenerateCa(new GenerateCaRequest { CommonName = "Facts Root", KeyAlgorithm = algorithm, ValidityDays = 365 });

        var facts = IssuerCertificateFacts.Read(generator.GetCaCertificatePem());

        Assert.Contains("CN=Facts Root", facts.SubjectDn);
        Assert.True(facts.IsCa);
        Assert.True(facts.IsSelfSigned);
        Assert.True(facts.HasKeyCertSign);
        Assert.Null(facts.PathLengthConstraint);
        Assert.Empty(facts.PermittedDnsSuffixes);
        Assert.Equal(algorithm, facts.KeyAlgorithm);
        Assert.Equal(64, facts.SpkiSha256.Length);
        Assert.Equal(facts.SpkiSha256, facts.SpkiSha256.ToLowerInvariant());
        Assert.False(string.IsNullOrEmpty(facts.SubjectKeyIdentifier));
    }

    [Fact]
    public void ApplyTo_CopiesFactsAndListsAsJson()
    {
        var generator = new CertificateGenerator(new EphemeralDataProtectionProvider(),
            new CaDataOptions { Directory = _dir }, NullLogger<CertificateGenerator>.Instance);
        generator.GenerateCa(new GenerateCaRequest { CommonName = "Apply Root", ValidityDays = 365 });
        var issuer = new Issuer();

        IssuerCertificateFacts.Read(generator.GetCaCertificatePem()).ApplyTo(issuer);

        Assert.Contains("CN=Apply Root", issuer.SubjectDn);
        Assert.Equal("[]", issuer.PermittedDnsSuffixesJson);
        Assert.Equal(CertificateKeyAlgorithm.Rsa, issuer.KeyAlgorithm);
        Assert.NotNull(issuer.ValidTo);
    }
}
