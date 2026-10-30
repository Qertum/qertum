using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

/// <summary>
/// Renewing a root CA certificate gives the CA a new key and certificate and makes it the default issuer, so
/// issuance goes on without setting up a new CA. A revoked root that is not renewed still needs setup
/// (<see cref="RevokedRootTests"/>). Until this, approving the renewal handed back the old (revoked) certificate
/// and nothing changed.
/// </summary>
public sealed class RootRenewalTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;
    private static readonly CaSettings Settings = new() { PqcStage = PqcStage.Off };

    private static async Task<(IssuerId Root, CertificateRequestId RootRequest)> SetUpAsync(IssuerApiHost host, bool afterRevokedFlag = false)
    {
        host.Kit.InitializeLegacy("Old Root");
        var rootId = await host.DefaultIssuerIdAsync(Ct);
        await using var db = host.Kit.Database.CreateContext();
        var issuer = await db.Issuers.AsNoTracking().SingleAsync(i => i.Id == rootId, Ct);
        var request = new CertificateRequest
        {
            CommonName = "Old Root", RequestedBy = "seed", Type = WellKnownCertificateTypes.RootCa,
            Status = CertificateRequestStatus.Issued, SerialNumber = issuer.SerialNumber, IssuerId = rootId,
            KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256,
            PropertiesJson = JsonSerializer.Serialize(new RootCaProperties
            {
                OrganizationName = "Example Oy", Country = "FI", ValidityDays = 3650, AfterRevokedIssuer = afterRevokedFlag
            })
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(Ct);
        return (rootId, request.Id);
    }

    private static async Task<CertificateRequest> RenewAsync(IssuerApiHost host, CertificateRequestId rootRequest)
    {
        var response = await host.Admin().PostAsync($"/v1/certificate-requests/{(Guid)rootRequest}/renew", null, Ct);
        Assert.True(response.IsSuccessStatusCode, $"renew answered {(int)response.StatusCode}: {await response.Content.ReadAsStringAsync(Ct)}");
        return (await response.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!;
    }

    private static async Task<GeneratedCertificate> SignAsync(IssuerApiHost host, CertificateRequestId id)
    {
        using var scope = host.Factory.Services.CreateScope();
        var row = (await scope.ServiceProvider.GetRequiredService<ICertificateRequestService>().GetByIdAsync(id, Ct))!;
        return await scope.ServiceProvider.GetRequiredService<IssuanceSigner>().SignAsync(row, Settings, Ct);
    }

    private static async Task<Issuer> IssuerAsync(IssuerApiHost host, IssuerId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        return await db.Issuers.AsNoTracking().SingleAsync(i => i.Id == id, Ct);
    }

    [Fact]
    public async Task ARevokedRoot_Renewed_IssuesAgainUnderANewKey_AndTheOldOneKeepsItsCrl()
    {
        await using var host = new IssuerApiHost();
        var (rootId, rootRequest) = await SetUpAsync(host);
        var old = await IssuerAsync(host, rootId);
        await host.Admin().PostAsJsonAsync($"/v1/certificate-requests/{(Guid)rootRequest}/revoke", new RevokeRequest("superseded"), Ct);
        Assert.Null(await host.Registry.GetDefaultAsync(Ct));

        var renewal = await RenewAsync(host, rootRequest);
        var signed = await SignAsync(host, renewal.Id);

        var next = await host.Registry.GetDefaultAsync(Ct);
        Assert.NotNull(next);
        Assert.Equal((Guid)renewal.Id, next!.Issuer.Id.Value);
        Assert.Equal(next.Issuer.Id, signed.IssuerId);
        Assert.True(next.CanIssue);
        Assert.NotEqual(old.SpkiSha256, next.Issuer.SpkiSha256);           // a new key
        Assert.NotEqual(old.CertificatePem, signed.CertificatePem);
        Assert.Contains("CN=Old Root", next.Issuer.SubjectDn);              // the same CA name
        Assert.Contains("O=Example Oy", next.Issuer.SubjectDn);
        Assert.Equal(old.Name, next.Issuer.Name);                           // the same issuer name, no "(2)"

        var revoked = await IssuerAsync(host, rootId);
        Assert.Equal(IssuerStatus.Retired, revoked.Status);
        Assert.NotNull(revoked.RevokedAtUtc);
        Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync($"/crl/{rootId}", Ct)).StatusCode);

        var status = await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct);
        Assert.True(status!.IsInitialized);
        Assert.False(status.IssuerRevoked);
        var create = await host.Admin().PostAsJsonAsync("/v1/certificate-requests", new { commonName = "after.example", type = "WebServer" }, Ct);
        Assert.Equal(HttpStatusCode.Created, create.StatusCode);
    }

    [Fact]
    public async Task ALiveRoot_Renewed_BecomesTheDefault_TheOldIsRetiredNotDestroyed_AndPinsMove()
    {
        await using var host = new IssuerApiHost();
        // The original carries the after-revocation flag; the renewal must not inherit it.
        var (rootId, rootRequest) = await SetUpAsync(host, afterRevokedFlag: true);
        await using (var db = host.Kit.Database.CreateContext())
        {
            var template = await db.CertificateTemplates.SingleAsync(t => t.TypeKey == "WebServer", Ct);
            template.IssuerId = rootId;
            await db.SaveChangesAsync(Ct);
        }

        var renewal = await RenewAsync(host, rootRequest);
        Assert.DoesNotContain("\"AfterRevokedIssuer\":true", renewal.PropertiesJson);
        await SignAsync(host, renewal.Id);

        var next = await host.Registry.GetDefaultAsync(Ct);
        Assert.Equal((Guid)renewal.Id, next!.Issuer.Id.Value);
        var old = await IssuerAsync(host, rootId);
        Assert.Equal(IssuerStatus.Retired, old.Status);
        Assert.False(old.IsDefault);
        Assert.Null(old.RevokedAtUtc);
        Assert.Equal(old.Name, next.Issuer.Name);  // both roots carry the name; serial and dates tell them apart
        Assert.Equal(rootId, next.Issuer.RenewalOfIssuerId);
        Assert.True(File.Exists(Path.Combine(host.Kit.CaDataDirectory, "ca.key"))); // kept: its certificates stay checkable
        Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync($"/crl/{rootId}", Ct)).StatusCode);
        await using (var db = host.Kit.Database.CreateContext())
            Assert.Equal(next.Issuer.Id, (await db.CertificateTemplates.SingleAsync(t => t.TypeKey == "WebServer", Ct)).IssuerId);
    }

    [Fact]
    public async Task ARenewalSignedAfterANewCaWasSetUp_IsRefused()
    {
        await using var host = new IssuerApiHost();
        var (_, rootRequest) = await SetUpAsync(host);
        await host.Admin().PostAsJsonAsync($"/v1/certificate-requests/{(Guid)rootRequest}/revoke", new RevokeRequest(null), Ct);
        var renewal = await RenewAsync(host, rootRequest);
        var other = await host.Kit.AddOnlineRootAsync("Set Up Meanwhile");
        await host.Registry.InvalidateAsync(Ct);
        (await host.Admin().PostAsync($"/v1/issuers/{other.Id}/make-default", null, Ct)).EnsureSuccessStatusCode();

        await Assert.ThrowsAsync<InvalidOperationException>(() => SignAsync(host, renewal.Id));
        Assert.Equal(other.Id, await host.DefaultIssuerIdAsync(Ct));
    }

    [Fact]
    public async Task AutoRevokeOnRenewal_LeavesTheRenewedRootAlone()
    {
        // Revoking the old root would retire everything it signed; a root renewal retires it instead.
        await using var host = new IssuerApiHost();
        var (rootId, rootRequest) = await SetUpAsync(host);
        await using (var db = host.Kit.Database.CreateContext())
        {
            var settings = await db.Settings.SingleOrDefaultAsync(s => s.Id == 1, Ct);
            if (settings is null) db.Settings.Add(settings = new CaSettings { Id = 1, PqcStage = PqcStage.Off });
            settings.AutoRevokeOnRenewal = true;
            await db.SaveChangesAsync(Ct);
        }
        var renewal = await RenewAsync(host, rootRequest);

        var approve = await host.Sub("second-admin").PostAsJsonAsync($"/v1/certificate-requests/{(Guid)renewal.Id}/approve", new { }, Ct);

        Assert.True(approve.IsSuccessStatusCode, $"approve answered {(int)approve.StatusCode}: {await approve.Content.ReadAsStringAsync(Ct)}");
        await using (var db = host.Kit.Database.CreateContext())
            Assert.Equal(CertificateRequestStatus.Issued, (await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == rootRequest, Ct)).Status);
        Assert.Null((await IssuerAsync(host, rootId)).RevokedAtUtc);
    }

    [Fact]
    public async Task AfterARootRenewal_AnIntermediateRenewsUnderTheNewRoot()
    {
        await using var host = new IssuerApiHost();
        var (rootId, rootRequest) = await SetUpAsync(host);
        var created = await (await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", new CreateIntermediateRequest
        {
            Name = "Issuing CA", CommonName = "Issuing CA", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256,
            ValidityDays = 365, PathLength = 0, ParentIssuerId = rootId
        }, Ct)).Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct);
        var renewal = await RenewAsync(host, rootRequest);
        await SignAsync(host, renewal.Id);
        var newRoot = (await host.Registry.GetDefaultAsync(Ct))!.Issuer.Id;

        var response = await IntermediateRenewalTests.RenewAsync(host, created!.Issuer.Id);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var renewed = (await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct))!;
        Assert.Equal(newRoot, renewed.Issuer.ParentIssuerId);
        var chain = await host.Admin().GetStringAsync($"/v1/issuers/{renewed.Issuer.Id}/chain", Ct);
        Assert.Contains((await IssuerAsync(host, newRoot)).CertificatePem!.Trim(), chain);
    }
}
