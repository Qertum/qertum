using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

/// <summary>
/// The routes every certificate shares (update, renew, approve, revoke) also reach CA certificates, and they were
/// guarded only by the ordinary workflow permissions: a leaf operator could approve a request by editing its status,
/// renew and approve the root (which replaces the trust anchor), or revoke a CA certificate (which retires the issuer
/// and, under HardStop, everything below it). A CA certificate now needs <c>certificates.ca</c> on each of these paths.
/// Found by GitHub AI Scan on the 1.0.0-rc4.1 snapshot.
/// </summary>
public sealed class CaCertificateAuthorizationTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly string[] LeafOperator =
        [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate, AppPermissions.CertificatesManage];

    private static readonly string[] CaOperator =
        [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate, AppPermissions.CertificatesManage, AppPermissions.CertificatesCa];

    private static async Task<(IssuerId Root, CertificateRequestId RootRequest)> SetUpAsync(IssuerApiHost host)
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
            PropertiesJson = JsonSerializer.Serialize(new RootCaProperties { OrganizationName = "Example Oy", Country = "FI", ValidityDays = 3650 })
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(Ct);
        await host.GrantAsync("leaf-op", LeafOperator);
        await host.GrantAsync("ca-op", CaOperator);
        return (rootId, request.Id);
    }

    private static async Task<CertificateRequest> StatusAsync(IssuerApiHost host, Guid id) =>
        (await host.Admin().GetFromJsonAsync<CertificateRequest>($"/v1/certificate-requests/{id}", Ct))!;

    [Fact]
    public async Task Update_NeverChangesTheStatus()
    {
        await using var host = new IssuerApiHost();
        await SetUpAsync(host);
        var created = await host.Role("ca-op").PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = "sub.example.com", Type = "SubordinateCA", PropertiesJson = "{}" }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!.Id;

        // An old client, or someone probing, still sends a status: it must not move the request.
        using var body = new StringContent(
            """{"commonName":"sub.example.com","type":"SubordinateCA","propertiesJson":"{}","status":"Approved"}""",
            Encoding.UTF8, "application/json");
        var response = await host.Role("ca-op").PutAsync($"/v1/certificate-requests/{(Guid)id}", body, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(CertificateRequestStatus.Pending, (await StatusAsync(host, (Guid)id)).Status);
    }

    [Fact]
    public async Task RenewingTheRoot_NeedsTheCaPermission_AndSoDoesApprovingTheRenewal()
    {
        await using var host = new IssuerApiHost();
        var (_, rootRequest) = await SetUpAsync(host);

        var refused = await host.Role("leaf-op").PostAsync($"/v1/certificate-requests/{(Guid)rootRequest}/renew", null, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains("caPermission", await refused.Content.ReadAsStringAsync(Ct));

        var renewed = await host.Role("ca-op").PostAsync($"/v1/certificate-requests/{(Guid)rootRequest}/renew", null, Ct);
        Assert.Equal(HttpStatusCode.Created, renewed.StatusCode);
        var renewal = (await renewed.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!;

        var approval = await host.Role("leaf-op").PostAsync($"/v1/certificate-requests/{(Guid)renewal.Id}/approve", null, Ct);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, approval.StatusCode);
        Assert.Contains("caPermission", await approval.Content.ReadAsStringAsync(Ct));
        Assert.Equal(CertificateRequestStatus.Pending, (await StatusAsync(host, (Guid)renewal.Id)).Status);
    }

    [Fact]
    public async Task ARootRenewal_NeedsAnApproverOtherThanItsRequester()
    {
        // Root requests skipped the independent-approver rule, so one certificates.ca holder could replace the trust
        // anchor alone while RequireIndependentCaApproval was on (AI Scan #332 on 1.0.0-rc4.2).
        await using var host = new IssuerApiHost();
        var (_, rootRequest) = await SetUpAsync(host);
        var renewed = await host.Sub("alice", "ca-op").PostAsync($"/v1/certificate-requests/{(Guid)rootRequest}/renew", null, Ct);
        Assert.Equal(HttpStatusCode.Created, renewed.StatusCode);
        var renewal = (await renewed.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!;

        var self = await host.Sub("alice", "ca-op").PostAsync($"/v1/certificate-requests/{(Guid)renewal.Id}/approve", null, Ct);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, self.StatusCode);
        Assert.Contains("selfApproval", await self.Content.ReadAsStringAsync(Ct));
        Assert.Equal(CertificateRequestStatus.Pending, (await StatusAsync(host, (Guid)renewal.Id)).Status);

        var other = await host.Sub("bob", "ca-op").PostAsync($"/v1/certificate-requests/{(Guid)renewal.Id}/approve", null, Ct);
        Assert.True(other.IsSuccessStatusCode, await other.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task RevokingACaCertificate_NeedsTheCaPermission_AndLeavesTheIssuerAloneWithout()
    {
        await using var host = new IssuerApiHost();
        var (rootId, rootRequest) = await SetUpAsync(host);

        var refused = await host.Role("leaf-op").PostAsJsonAsync($"/v1/certificate-requests/{(Guid)rootRequest}/revoke",
            new RevokeRequest("keyCompromise"), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Contains("certificates.ca", await refused.Content.ReadAsStringAsync(Ct));
        Assert.Equal(CertificateRequestStatus.Issued, (await StatusAsync(host, (Guid)rootRequest)).Status);
        Assert.Equal(rootId, (await host.Registry.GetDefaultAsync(Ct))!.Issuer.Id);

        var allowed = await host.Role("ca-op").PostAsJsonAsync($"/v1/certificate-requests/{(Guid)rootRequest}/revoke",
            new RevokeRequest("keyCompromise"), Ct);
        Assert.Equal(HttpStatusCode.Accepted, allowed.StatusCode);
    }
}
