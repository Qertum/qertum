using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class RequesterRoleApiTests
{
    [Fact]
    public async Task RestCreate_ByNonMember_Is400WithTheRule()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            // The certificate-requests group needs view; create needs create.
            db.RolePermissions.AddRange(
                new RolePermission { Role = "req-creator", Permission = AppPermissions.CertificatesView },
                new RolePermission { Role = "req-creator", Permission = AppPermissions.CertificatesCreate });
            await db.SaveChangesAsync(ct);
            await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", requesterRoles: ["ops"], ct: ct);
        }
        using var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "req-creator");

        var response = await client.PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = "rest.example.com", Type = "WebServer", PropertiesJson = "{}" }, ct);

        // Create-stage policy violations answer 400 (approval-stage ones 422), as for every other rule.
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("requesterRole", await response.Content.ReadAsStringAsync(ct));
    }
}
