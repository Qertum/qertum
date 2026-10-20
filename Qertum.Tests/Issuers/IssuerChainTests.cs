using Microsoft.Extensions.DependencyInjection;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using Qertum.Services;
using Qertum.Services.Acme;
using Qertum.Services.Est;
using Qertum.Services.Issuers;

using CertificateRequest = Qertum.Services.CertificateRequest;

namespace Qertum.Tests.Issuers;

public sealed class IssuerChainTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>Legacy root + a second root re-parented under it as a stand-in intermediate (chain = 2 certs).</summary>
    private static async Task<Issuer> StandInIntermediateAsync(IssuerApiHost host)
    {
        host.Kit.InitializeLegacy();
        var legacyId = await host.DefaultIssuerIdAsync(Ct);
        var mid = await host.Kit.AddOnlineRootAsync("Stand-in Intermediate");
        await using var db = host.Kit.Database.CreateContext();
        var row = await db.Issuers.FindAsync([mid.Id], Ct);
        row!.Kind = IssuerKind.Intermediate;
        row.ParentIssuerId = legacyId;
        await db.SaveChangesAsync(Ct);
        await host.Registry.InvalidateAsync(Ct);
        return row;
    }

    private static async Task<Guid> SeedWithKeyAsync(IssuerApiHost host, IssuerId? issuerId, ICertificateGenerator signer)
    {
        var issued = signer.GenerateCertificate(new CertificateRequest { CommonName = "pfx.example" }, new CaSettings { PqcStage = PqcStage.Off });
        // Through the host's scope: the private key column is encrypted with the host's key ring.
        using var scope = host.Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var row = new CertificateRequest
        {
            CommonName = "pfx.example", RequestedBy = "Test User", Status = CertificateRequestStatus.Issued,
            CertificatePem = issued.CertificatePem, PrivateKeyPem = issued.PrivateKeyPem, SerialNumber = issued.SerialNumber,
            IssuerId = issuerId
        };
        db.CertificateRequests.Add(row);
        await db.SaveChangesAsync(Ct);
        return row.Id;
    }

    private static async Task<X509Certificate2Collection> PfxAsync(IssuerApiHost host, Guid id)
    {
        var response = await host.Admin().PostAsJsonAsync($"/v1/certificate-requests/{id}/pfx",
            new ExportPfxRequest("pw", IncludeChain: true), Ct);
        response.EnsureSuccessStatusCode();
        return X509CertificateLoader.LoadPkcs12Collection(await response.Content.ReadAsByteArrayAsync(Ct), "pw");
    }

    [Fact]
    public async Task Pfx_IncludeChain_CarriesTheIssuingChain()
    {
        await using var host = new IssuerApiHost();
        var mid = await StandInIntermediateAsync(host);
        var id = await SeedWithKeyAsync(host, mid.Id, host.Kit.NewGenerator(host.Kit.Storage.OptionsFor(mid)));

        Assert.Equal(3, (await PfxAsync(host, id)).Count);
    }

    [Fact]
    public async Task Pfx_ForALegacyRow_ChainIsTheLegacyRoot()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var id = await SeedWithKeyAsync(host, null, host.Kit.Legacy);

        Assert.Equal(2, (await PfxAsync(host, id)).Count);
    }

    [Fact]
    public void AcmeChain_IsLeafThenIssuerChain_AndUnchangedForASingleRoot()
    {
        Assert.Equal("LEAF\nROOT", AcmeEndpointMappings.BuildChainPem("LEAF", ["ROOT"]));
        Assert.Equal("LEAF\nMID\nROOT", AcmeEndpointMappings.BuildChainPem("LEAF", ["MID", "ROOT"]));
    }

    [Fact]
    public async Task EstCacerts_ReturnsTheDefaultIssuersWholeChain()
    {
        // EST lives in its own host; exercise the shared helper instead of booting it.
        await using var host = new IssuerApiHost();
        var mid = await StandInIntermediateAsync(host);
        await using (var db = host.Kit.Database.CreateContext())
        {
            foreach (var row in db.Issuers) row.IsDefault = false;
            await db.SaveChangesAsync(Ct);
            (await db.Issuers.FindAsync([mid.Id], Ct))!.IsDefault = true;
            await db.SaveChangesAsync(Ct);
        }
        await host.Registry.InvalidateAsync(Ct);

        var certificates = await EstEndpointMappings.CaCertificatesAsync(host.Registry, Ct);

        Assert.Equal(2, certificates.Count);
    }

    [Fact]
    public async Task Reenroll_TrustSet_AcceptsAnyActiveOrRetiredPath_AndRefusesUnknownRoots()
    {
        using var kit = new IssuerTestKit();
        var a = kit.NewGenerator(new CaDataOptions { Directory = Path.Combine(kit.CaDataDirectory, "a") });
        a.GenerateCa(new GenerateCaRequest { CommonName = "A", ValidityDays = 30 });
        var b = kit.NewGenerator(new CaDataOptions { Directory = Path.Combine(kit.CaDataDirectory, "b") });
        b.GenerateCa(new GenerateCaRequest { CommonName = "B", ValidityDays = 30 });
        using var leaf = X509Certificate2.CreateFromPem(a.GenerateCertificate(new CertificateRequest { CommonName = "d.example" }, new CaSettings { PqcStage = PqcStage.Off }).CertificatePem);
        using var rootA = X509Certificate2.CreateFromPem(a.GetCaCertificatePem());
        using var rootB = X509Certificate2.CreateFromPem(b.GetCaCertificatePem());
        var none = new FakeRevocationStatusService(new Dictionary<string, OcspCertificateStatus>());

        Assert.True(await EstEndpointMappings.VerifyReenrollCertificateAsync(leaf, [rootB, rootA], [], none, Ct));
        Assert.False(await EstEndpointMappings.VerifyReenrollCertificateAsync(leaf, [rootB], [], none, Ct));
    }
}
