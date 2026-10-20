using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class CertificateInventoryApiTests
{
    [Fact]
    public async Task Inventory_ReturnsCertificateFactsWithoutPem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var certificate = TestCertificates.CreateSelfSigned("CN=inventory-api.local");
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = "inventory-api.local", RequestedBy = "Alice", RequestedBySubject = "owner-1",
                Status = CertificateRequestStatus.Issued, CertificatePem = certificate.ExportCertificatePem(),
                PqcCertificatePem = certificate.ExportCertificatePem()
            });
            await db.SaveChangesAsync(ct);
        }

        using var http = Admin(factory);
        var client = new CertificateRequestsApiClient(http);
        var page = await client.GetCertificateInventoryAsync(1, 1, ct);
        var response = await http.GetAsync("/v1/certificate-inventory?page=2&pageSize=1", ct);
        var json = await response.Content.ReadAsStringAsync(ct);

        Assert.Equal(2, page.TotalCount);
        Assert.Equal("primary", Assert.Single(page.Items).Leg);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"leg\":\"pqc\"", json);
        Assert.DoesNotContain("certificatePem", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("privateKey", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Inventory_RequiresCertificatesView()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission
            {
                Role = "inventory-creator", Permission = AppPermissions.CertificatesCreate
            });
            await db.SaveChangesAsync(ct);
        }
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "inventory-creator");

        var response = await client.GetAsync("/v1/certificate-inventory", ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }
}
