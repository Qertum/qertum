using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Security;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

/// <summary>
/// Revoking the certificate an issuer stands on takes that issuer out of service: it stops issuing, stops being the
/// default, keeps answering CRL, and onboarding asks for a new root. Without this the revoked row was cosmetic and the
/// CA went on signing.
/// </summary>
public sealed class RevokedRootTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<CertificateRequestId> SeedRootRequestAsync(IssuerApiHost host, IssuerId issuerId, string serial)
    {
        await using var db = host.Kit.Database.CreateContext();
        var request = new CertificateRequest
        {
            CommonName = "Old Root", RequestedBy = "seed", Type = WellKnownCertificateTypes.RootCa,
            Status = CertificateRequestStatus.Issued, SerialNumber = serial, IssuerId = issuerId
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(Ct);
        return request.Id;
    }

    private static async Task<IssuerId> SeedChildAsync(IssuerApiHost host, IssuerId parent)
    {
        await using var db = host.Kit.Database.CreateContext();
        var child = new Issuer
        {
            Name = "Child CA", Kind = IssuerKind.Intermediate, ParentIssuerId = parent, KeyCustody = IssuerKeyCustody.Offline,
            Status = IssuerStatus.Active, SpkiSha256 = Guid.NewGuid().ToString("N"), SerialNumber = "ABCDEF",
            CreatedAtUtc = DateTime.UtcNow
        };
        db.Issuers.Add(child);
        await db.SaveChangesAsync(Ct);
        return child.Id;
    }

    private static async Task<Issuer> IssuerAsync(IssuerApiHost host, IssuerId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        return await db.Issuers.AsNoTracking().SingleAsync(i => i.Id == id, Ct);
    }

    private static async Task<(IssuerId Root, CertificateRequestId RootRequest)> SetUpAsync(IssuerApiHost host)
    {
        host.Kit.InitializeLegacy("Old Root");
        var rootId = await host.DefaultIssuerIdAsync(Ct);
        var serial = (await IssuerAsync(host, rootId)).SerialNumber!;
        return (rootId, await SeedRootRequestAsync(host, rootId, serial));
    }

    [Fact]
    public async Task RevokingTheRoot_HardStop_StopsIssuance_RetiresTheTree_AndKeepsTheCrl()
    {
        await using var host = new IssuerApiHost();
        var (rootId, rootRequest) = await SetUpAsync(host);
        var childId = await SeedChildAsync(host, rootId);

        var revoke = await host.Admin().PostAsJsonAsync($"/v1/certificate-requests/{(Guid)rootRequest}/revoke", new RevokeRequest("key compromise"), Ct);

        Assert.Equal(HttpStatusCode.Accepted, revoke.StatusCode);
        var root = await IssuerAsync(host, rootId);
        Assert.Equal(IssuerStatus.Retired, root.Status);
        Assert.False(root.IsDefault);
        Assert.NotNull(root.RevokedAtUtc);
        var child = await IssuerAsync(host, childId);
        Assert.Equal(IssuerStatus.Retired, child.Status);
        Assert.NotNull(child.RevokedAtUtc);

        Assert.Null(await host.Registry.GetDefaultAsync(Ct));
        var status = await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct);
        Assert.False(status!.IsInitialized);
        Assert.True(status.IssuerRevoked);
        var create = await host.Admin().PostAsJsonAsync("/v1/certificate-requests", new { commonName = "after.example", type = "WebServer" }, Ct);
        Assert.Equal(HttpStatusCode.Conflict, create.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync($"/crl/{rootId}", Ct)).StatusCode);
    }

    [Fact]
    public async Task RevokingTheRoot_Retire_RetiresOnlyThatIssuer()
    {
        await using var host = new IssuerApiHost();
        var (rootId, rootRequest) = await SetUpAsync(host);
        var childId = await SeedChildAsync(host, rootId);
        Assert.Equal(HttpStatusCode.OK, (await host.Admin().PutAsJsonAsync("/v1/settings/revoked-issuer", new { mode = "Retire" }, Ct)).StatusCode);

        await host.Admin().PostAsJsonAsync($"/v1/certificate-requests/{(Guid)rootRequest}/revoke", new RevokeRequest(null), Ct);

        Assert.Equal(IssuerStatus.Retired, (await IssuerAsync(host, rootId)).Status);
        var child = await IssuerAsync(host, childId);
        Assert.Equal(IssuerStatus.Active, child.Status);
        Assert.Null(child.RevokedAtUtc);
    }

    [Fact]
    public async Task RevokingAnOrdinaryCertificate_LeavesTheIssuerAlone()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var rootId = await host.DefaultIssuerIdAsync(Ct);
        await host.SeedIssuedAsync(rootId, host.Kit.Legacy, revoked: false, Ct, "leaf.example");
        Guid leaf;
        await using (var db = host.Kit.Database.CreateContext())
            leaf = (Guid)(await db.CertificateRequests.SingleAsync(r => r.CommonName == "leaf.example", Ct)).Id;

        var revoke = await host.Admin().PostAsJsonAsync($"/v1/certificate-requests/{leaf}/revoke", new RevokeRequest(null), Ct);

        Assert.Equal(HttpStatusCode.Accepted, revoke.StatusCode);
        var root = await IssuerAsync(host, rootId);
        Assert.Equal(IssuerStatus.Active, root.Status);
        Assert.True(root.IsDefault);
        Assert.Null(root.RevokedAtUtc);
    }

    [Fact]
    public async Task AfterAHardStop_ImportCreatesANewRootWithoutForce_AndTheOldOneKeepsServingItsCrl()
    {
        await using var host = new IssuerApiHost();
        var (rootId, rootRequest) = await SetUpAsync(host);
        await host.Admin().PostAsJsonAsync($"/v1/certificate-requests/{(Guid)rootRequest}/revoke", new RevokeRequest(null), Ct);
        var key = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256).GenerateCaKeyPair(new SecureRandom());
        var cert = CaCertificateBuilder.BuildRoot(new LocalKeyPairCaSigner(key),
            CaCertificateBuilder.SubjectName("New Root", null, null, null, null, null), DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddYears(10));

        var import = await host.Admin().PostAsJsonAsync("/v1/ca/import", new ImportCaRequest
        {
            CertificatePem = QertumKeyCodec.WriteCertificatePem(cert), PrivateKeyPem = QertumKeyCodec.WritePrivateKeyPem(key.Private)
        }, Ct);

        Assert.Equal(HttpStatusCode.OK, import.StatusCode);
        var next = await host.Registry.GetDefaultAsync(Ct);
        Assert.NotNull(next);
        Assert.NotEqual(rootId, next!.Issuer.Id);
        Assert.Contains("CN=New Root", next.Issuer.SubjectDn);
        Assert.True(next.CanIssue);
        Assert.Equal(IssuerStatus.Retired, (await IssuerAsync(host, rootId)).Status);
        Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync($"/crl/{rootId}", Ct)).StatusCode);
        Assert.True((await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.IsInitialized);
        Assert.False((await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct))!.IssuerRevoked);
    }

    [Fact]
    public async Task WithoutARevocation_ImportStillNeedsForce()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        var key = AlgorithmStrategyFactory.CreateIssuer(CertificateKeyAlgorithm.EcdsaP256).GenerateCaKeyPair(new SecureRandom());
        var cert = CaCertificateBuilder.BuildRoot(new LocalKeyPairCaSigner(key),
            CaCertificateBuilder.SubjectName("New Root", null, null, null, null, null), DateTime.UtcNow.AddMinutes(-5), DateTime.UtcNow.AddYears(10));

        var import = await host.Admin().PostAsJsonAsync("/v1/ca/import", new ImportCaRequest
        {
            CertificatePem = QertumKeyCodec.WriteCertificatePem(cert), PrivateKeyPem = QertumKeyCodec.WritePrivateKeyPem(key.Private)
        }, Ct);

        Assert.Equal(HttpStatusCode.Conflict, import.StatusCode);
    }

    [Fact]
    public async Task Setting_IsAdminOnly_ValidatesTheMode_AndSurvivesAGeneralSave()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");
        await host.GrantAsync("ops", AppPermissions.SettingsEdit);

        Assert.Equal(HttpStatusCode.Forbidden, (await host.Role("ops").PutAsJsonAsync("/v1/settings/revoked-issuer", new { mode = "Retire" }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await host.Admin().PutAsJsonAsync("/v1/settings/revoked-issuer", new { mode = "Nope" }, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await host.Admin().PutAsJsonAsync("/v1/settings/revoked-issuer", new { }, Ct)).StatusCode);

        var set = await host.Admin().PutAsJsonAsync("/v1/settings/revoked-issuer", new { mode = "Retire" }, Ct);
        Assert.Equal(RevokedIssuerMode.Retire, (await set.Content.ReadFromJsonAsync<CaSettings>(Ct))!.RevokedIssuerMode);

        var current = await host.Admin().GetFromJsonAsync<CaSettings>("/v1/settings", Ct);
        current!.RevokedIssuerMode = RevokedIssuerMode.HardStop;
        await host.Admin().PutAsJsonAsync("/v1/settings", current, Ct);
        Assert.Equal(RevokedIssuerMode.Retire, (await host.Admin().GetFromJsonAsync<CaSettings>("/v1/settings", Ct))!.RevokedIssuerMode);
    }

    [Fact]
    public async Task Setting_DefaultsToHardStop()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Old Root");

        var settings = await host.Admin().GetFromJsonAsync<CaSettings>("/v1/settings", Ct);

        Assert.Equal(RevokedIssuerMode.HardStop, settings!.RevokedIssuerMode);
    }
}
