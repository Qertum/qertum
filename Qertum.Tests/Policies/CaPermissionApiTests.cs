using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class CaPermissionApiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task RestCreate_OfACaTemplate_IsRefusedWithoutThePermission_AndAdmittedWithIt()
    {
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, Ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.AddRange(
                new RolePermission { Role = "leaf-op", Permission = AppPermissions.CertificatesView },
                new RolePermission { Role = "leaf-op", Permission = AppPermissions.CertificatesCreate },
                new RolePermission { Role = "ca-op", Permission = AppPermissions.CertificatesView },
                new RolePermission { Role = "ca-op", Permission = AppPermissions.CertificatesCreate },
                new RolePermission { Role = "ca-op", Permission = AppPermissions.CertificatesCa });
            await db.SaveChangesAsync(Ct);
        }

        var body = new CreateCertificateRequestRequest { CommonName = "ca.example.com", Type = "SubordinateCA", PropertiesJson = "{}" };

        using var leafOp = factory.CreateClient();
        leafOp.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "leaf-op");
        var refused = await leafOp.PostAsJsonAsync("/v1/certificate-requests", body, Ct);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Contains("caPermission", await refused.Content.ReadAsStringAsync(Ct));

        var preview = await leafOp.PostAsJsonAsync("/v1/certificate-requests/preview", body, Ct);
        Assert.Equal(HttpStatusCode.OK, preview.StatusCode);
        Assert.Contains("caPermission", await preview.Content.ReadAsStringAsync(Ct));

        using var caOp = factory.CreateClient();
        caOp.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "ca-op");
        Assert.Equal(HttpStatusCode.Created, (await caOp.PostAsJsonAsync("/v1/certificate-requests", body, Ct)).StatusCode);
    }

    private static async Task SeedRolesAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct, params (string Role, string[] Perms)[] roles)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        foreach (var (role, perms) in roles)
            foreach (var p in perms)
                db.RolePermissions.Add(new RolePermission { Role = role, Permission = p });
        await db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task RestApprove_RefusesSelfApproval_With422_AndAcceptsAnotherApprover()
    {
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, Ct);
        string[] all = [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate,
                        AppPermissions.CertificatesManage, AppPermissions.CertificatesCa];
        await SeedRolesAsync(factory, Ct, ("ca-requester", all), ("ca-approver", all));

        using var requester = factory.CreateClient();
        requester.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "ca-requester");
        var created = await requester.PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = "ca.example.com", Type = "SubordinateCA", PropertiesJson = "{}" }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!.Id;

        var self = await requester.PostAsync($"/v1/certificate-requests/{id}/approve", null, Ct);
        Assert.Equal(HttpStatusCode.UnprocessableEntity, self.StatusCode);
        Assert.Contains("selfApproval", await self.Content.ReadAsStringAsync(Ct));

        var preview = await requester.GetAsync($"/v1/certificate-requests/{id}/approval-preview", Ct);
        Assert.Contains("selfApproval", await preview.Content.ReadAsStringAsync(Ct));

        using var approver = factory.CreateClient();
        approver.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "ca-approver");
        Assert.Equal(HttpStatusCode.OK, (await approver.PostAsync($"/v1/certificate-requests/{id}/approve", null, Ct)).StatusCode);
    }

    [Fact]
    public async Task RestUpdate_RetypingToACaTemplate_IsRefusedWithoutThePermission()
    {
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, Ct);
        await SeedRolesAsync(factory, Ct, ("op", [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate, AppPermissions.CertificatesManage]));

        using var op = factory.CreateClient();
        op.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "op");
        var created = await op.PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = "leaf.example.com", Type = "WebServer", PropertiesJson = "{}" }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!.Id;

        var response = await op.PutAsJsonAsync($"/v1/certificate-requests/{id}",
            new UpdateCertificateRequestRequest { CommonName = "leaf.example.com", Type = "SubordinateCA", PropertiesJson = "{}" }, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("caPermission", await response.Content.ReadAsStringAsync(Ct));
    }

    [Fact]
    public async Task RestRenew_OfAnIssuedCaRequest_IsRefusedWithoutThePermission()
    {
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, Ct);
        await SeedRolesAsync(factory, Ct, ("op", [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate, AppPermissions.CertificatesManage]));
        CertificateRequestId id;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var row = new CertificateRequest
            {
                CommonName = "ca.example.com", RequestedBy = "x", Type = "SubordinateCA", Status = CertificateRequestStatus.Issued,
                ValidFrom = DateTime.UtcNow.AddDays(-10), ValidTo = DateTime.UtcNow.AddDays(20)
            };
            db.CertificateRequests.Add(row);
            await db.SaveChangesAsync(Ct);
            id = row.Id;
        }

        using var op = factory.CreateClient();
        op.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "op");
        var response = await op.PostAsync($"/v1/certificate-requests/{id}/renew", null, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("caPermission", await response.Content.ReadAsStringAsync(Ct));
    }
}
