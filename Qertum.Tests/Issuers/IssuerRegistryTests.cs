using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerRegistryTests : IDisposable
{
    private readonly IssuerTestKit _kit = new();

    public void Dispose() => _kit.Dispose();

    [Fact]
    public async Task NoCaAtAll_HasNoDefault_AndRefusesIssuance()
    {
        var ct = TestContext.Current.CancellationToken;
        var registry = _kit.NewRegistry();

        Assert.Null(await registry.GetDefaultAsync(ct));
        await Assert.ThrowsAsync<CaNotInitializedException>(() => registry.ForIssuanceAsync(null, ct));
    }

    [Fact]
    public async Task LegacyFiles_EmptyTable_AreBootstrappedAndSignWithTheLegacyGenerator()
    {
        var ct = TestContext.Current.CancellationToken;
        _kit.InitializeLegacy();
        var registry = _kit.NewRegistry();

        var handle = await registry.GetDefaultAsync(ct);

        Assert.NotNull(handle);
        Assert.True(handle.Issuer.LegacyFiles);
        Assert.Same(_kit.Legacy, handle.Generator);
        Assert.True(handle.CanIssue);
        Assert.Equal(new IssuerScope(handle.Issuer.Id, true), handle.Scope);
        await using var db = _kit.Database.CreateContext();
        Assert.Equal(1, await db.Issuers.CountAsync(ct));
    }

    [Fact]
    public async Task CaCreatedAfterAnEmptyLoad_IsRegisteredOnTheNextCall()
    {
        // Onboarding writes the CA in QueueConsumer; this host must not keep serving "no CA" from cache.
        var ct = TestContext.Current.CancellationToken;
        var registry = _kit.NewRegistry();
        Assert.Null(await registry.GetDefaultAsync(ct));

        _kit.InitializeLegacy();
        var handle = await registry.GetDefaultAsync(ct);

        Assert.NotNull(handle!.RecordedIssuerId);
    }

    [Fact]
    public async Task UnparseableLegacyCertificate_FallsBackToASyntheticHandle()
    {
        // Test stubs (and a corrupted ca.pem) cannot be registered; issuance must still work as before.
        var ct = TestContext.Current.CancellationToken;
        var registry = _kit.NewRegistry(new ThrowingPemGenerator());

        var handle = await registry.GetDefaultAsync(ct);

        Assert.NotNull(handle);
        Assert.Null(handle.RecordedIssuerId);
        Assert.True(handle.Issuer.LegacyFiles);
        Assert.True(handle.CanIssue);
    }

    [Fact]
    public async Task NonLegacyIssuer_GetsItsOwnGenerator_ThatSignsAsThatIssuer()
    {
        var ct = TestContext.Current.CancellationToken;
        var root = await _kit.AddOnlineRootAsync("Second Root", isDefault: true);
        var registry = _kit.NewRegistry();

        var handle = await registry.GetDefaultAsync(ct);
        var leaf = handle!.Generator!.GenerateCertificate(new CertificateRequest { CommonName = "leaf.example" }, new CaSettings { PqcStage = PqcStage.Off });

        var leafCert = QertumKeyCodec.ReadCertificatePem(leaf.CertificatePem)!;
        var rootCert = QertumKeyCodec.ReadCertificatePem(root.CertificatePem!)!;
        Assert.Equal(rootCert.SubjectDN.ToString(), leafCert.IssuerDN.ToString());
        Assert.True(leafCert.IsSignatureValid(QertumKeyCodec.VerifierFor(QertumKeyCodec.PublicKeyOf(rootCert))));
    }

    [Fact]
    public async Task PinnedRetiredIssuer_RefusesIssuance()
    {
        var ct = TestContext.Current.CancellationToken;
        await _kit.AddOnlineRootAsync("Default", isDefault: true);
        var retired = await _kit.AddOnlineRootAsync("Old", status: IssuerStatus.Retired);
        var registry = _kit.NewRegistry();

        var ex = await Assert.ThrowsAsync<IssuerNotActiveException>(() =>
            registry.ForIssuanceAsync(new CertificateTemplate { TypeKey = "T", IssuerId = retired.Id }, ct));
        Assert.Contains("Old", ex.Message);
        Assert.IsAssignableFrom<CaNotInitializedException>(ex);

        var retiredHandle = await registry.GetAsync(retired.Id, ct);
        Assert.True(retiredHandle!.CanSignRevocation);
        Assert.False(retiredHandle.CanIssue);
    }

    [Fact]
    public async Task ChainFor_WalksUpToAndIncludingTheRoot()
    {
        var ct = TestContext.Current.CancellationToken;
        await using (var db = _kit.Database.CreateContext())
        {
            var root = IssuerModelTests.Row("root");
            root.CertificatePem = "ROOT";
            var mid = IssuerModelTests.Row("mid");
            mid.Kind = IssuerKind.Intermediate; mid.ParentIssuerId = root.Id; mid.CertificatePem = "MID";
            var leafCa = IssuerModelTests.Row("issuing", isDefault: false);
            leafCa.Kind = IssuerKind.Intermediate; leafCa.ParentIssuerId = mid.Id; leafCa.CertificatePem = "ISSUING";
            db.Issuers.AddRange(root, mid, leafCa);
            await db.SaveChangesAsync(ct);

            var chain = await _kit.NewRegistry().ChainForAsync(leafCa.Id, ct);
            Assert.Equal(["ISSUING", "MID", "ROOT"], chain);
        }
    }

    [Fact]
    public async Task Invalidate_MakesAnotherHostSeeTheChange()
    {
        var ct = TestContext.Current.CancellationToken;
        var first = await _kit.AddOnlineRootAsync("First", isDefault: true);
        var second = await _kit.AddOnlineRootAsync("Second");
        var hostA = _kit.NewRegistry();
        var hostB = _kit.NewRegistry();
        Assert.Equal(first.Id, (await hostB.GetDefaultAsync(ct))!.Issuer.Id);

        await using (var db = _kit.Database.CreateContext())
        {
            await db.Issuers.Where(i => i.Id == first.Id).ExecuteUpdateAsync(s => s.SetProperty(i => i.IsDefault, false), ct);
            await db.Issuers.Where(i => i.Id == second.Id).ExecuteUpdateAsync(s => s.SetProperty(i => i.IsDefault, true), ct);
        }
        await hostA.InvalidateAsync(ct);

        Assert.Equal(second.Id, (await hostB.GetDefaultAsync(ct))!.Issuer.Id);
    }

    [Fact]
    public async Task DestroyedIssuer_LeftoverKeyFileIsDeletedOnLoad()
    {
        // Completes a force replace that crashed between the DB commit and the file delete.
        var ct = TestContext.Current.CancellationToken;
        await _kit.AddOnlineRootAsync("Keep", isDefault: true);
        var destroyed = await _kit.AddOnlineRootAsync("Gone", status: IssuerStatus.Destroyed);
        Assert.True(_kit.Storage.HasKeyFile(destroyed));

        await _kit.NewRegistry().GetAllAsync(ct);

        Assert.False(_kit.Storage.HasKeyFile(destroyed));
        Assert.Null((await _kit.NewRegistry().GetAsync(destroyed.Id, ct))!.Generator);
    }

    [Fact]
    public async Task ForRequest_NullIssuerId_IsTheLegacyIssuer()
    {
        var ct = TestContext.Current.CancellationToken;
        _kit.InitializeLegacy();
        var registry = _kit.NewRegistry();

        var handle = await registry.ForRequestAsync(new CertificateRequest { CommonName = "old", IssuerId = null }, ct);

        Assert.True(handle!.Issuer.LegacyFiles);
    }

    private sealed class ThrowingPemGenerator : ICertificateGenerator
    {
        public bool IsInitialized => true;
        public string GetCaCertificatePem() => "not a pem";
        public CaStatusResponse GetCaStatus() => new() { IsInitialized = true };
        public GeneratedCertificate GenerateCertificate(CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => new();
        public GeneratedCertificate GenerateFromCsr(string csrDerBase64Url, CertificateRequest request, CaSettings? caSettings, CertificateTemplate? template = null) => new();
        public byte[] GenerateCrl(IReadOnlyList<CertificateRequest> revokedRequests, CaSettings? caSettings = null, long crlNumber = 0, DateTime? thisUpdateUtc = null) => [];
        public byte[] GenerateDeltaCrl(IReadOnlyList<CertificateRequest> revokedSinceBase, CaSettings? caSettings, long crlNumber, long baseCrlNumber, DateTime? thisUpdateUtc = null) => [];
        public IReadOnlyList<string> ReadOcspRequestSerials(byte[] derRequest) => [];
        public byte[] GenerateOcspResponse(byte[] derRequest, IReadOnlyDictionary<string, OcspCertificateStatus> statuses, CaSettings? caSettings = null) => [];
        public GeneratedCertificate GenerateCa(GenerateCaRequest request) => throw new NotSupportedException();
        public void ImportCa(ImportCaRequest request) => throw new NotSupportedException();
    }
}
