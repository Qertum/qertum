using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuanceSignerTests : IDisposable
{
    private readonly IssuerTestKit _kit = new();

    public void Dispose() => _kit.Dispose();

    private async Task<(IssuanceSigner Signer, IssuerRegistry Registry)> CreateAsync()
    {
        var registry = _kit.NewRegistry();
        // Not disposed: the signer keeps using this scope's DbContext for the whole test.
        var scope = _kit.Scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var templates = new CertificateTemplateService(db, new NullAuditLog(), new NullWebhooks());
        return (IssuanceSignerFactory.Create(_kit, registry, db, templates), registry);
    }

    [Fact]
    public async Task Leaf_IsSignedByTheDefaultIssuer_AndStampedWithItsId()
    {
        var ct = TestContext.Current.CancellationToken;
        var root = await _kit.AddOnlineRootAsync("Default Root", isDefault: true);
        var (signer, _) = await CreateAsync();

        var result = await signer.SignAsync(new CertificateRequest { CommonName = "a.example", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off }, ct);

        Assert.Equal(root.Id, result.IssuerId);
        var leaf = QertumKeyCodec.ReadCertificatePem(result.CertificatePem)!;
        Assert.Contains("CN=Default Root", leaf.IssuerDN.ToString());
    }

    [Fact]
    public async Task Leaf_UnderTheLegacyIssuer_IsStampedWithTheLegacyRow()
    {
        var ct = TestContext.Current.CancellationToken;
        _kit.InitializeLegacy();
        var (signer, registry) = await CreateAsync();

        var result = await signer.SignAsync(new CertificateRequest { CommonName = "b.example", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off }, ct);

        Assert.Equal((await registry.GetDefaultAsync(ct))!.Issuer.Id, result.IssuerId);
    }

    [Fact]
    public async Task RootCaRequest_OnAFreshServer_CreatesTheLegacyCaAndRegistersIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var (signer, registry) = await CreateAsync();

        var result = await signer.SignAsync(new CertificateRequest
        {
            CommonName = "Fresh Root", Type = WellKnownCertificateTypes.RootCa, KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256,
            PropertiesJson = "{\"ValidityDays\":365}"
        }, new CaSettings { PqcStage = PqcStage.Off }, ct);

        Assert.True(_kit.Legacy.IsInitialized);
        var handle = await registry.GetDefaultAsync(ct);
        Assert.True(handle!.Issuer.LegacyFiles);
        Assert.Equal(handle.Issuer.Id, result.IssuerId);
    }

    [Fact]
    public async Task NoCa_RefusesALeaf()
    {
        var ct = TestContext.Current.CancellationToken;
        var (signer, _) = await CreateAsync();

        await Assert.ThrowsAsync<CaNotInitializedException>(() =>
            signer.SignAsync(new CertificateRequest { CommonName = "c.example", Type = "WebServer" }, new CaSettings { PqcStage = PqcStage.Off }, ct));
    }
}
