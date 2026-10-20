using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class ObservedRoleMiddlewareTests
{
    [Fact]
    public async Task AuthenticatedRequest_RecordsItsRoles_AnonymousRecordsNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);

        using var anonymous = factory.CreateClient();
        await anonymous.GetAsync("/v1/me/access", ct);

        using var auditor = RolePermissionsApiTests.AsRole(factory, "auditors");
        var response = await auditor.GetAsync("/v1/me/access", ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var roles = await db.ObservedRoles.AsNoTracking().Select(r => r.Role).ToListAsync(ct);
        Assert.Equal(["auditors"], roles);
    }
}
