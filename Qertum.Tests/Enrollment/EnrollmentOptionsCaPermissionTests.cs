using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Qertum.Services;
using Qertum.Services.Policies;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Enrollment;

public sealed class EnrollmentOptionsCaPermissionTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static Task<EnrollmentOptionsResponse> Options(PolicyTestDb scope, CallerContext? caller) =>
        scope.CreateEnrollmentOptionsService().GetAsync(requester: null, caller, Ct);

    [Fact]
    public async Task WithoutThePermission_TheSubordinateCaTemplateAndPurposeAreHidden()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        var options = await Options(scope, new CallerContext("s", "u", IsAdmin: false, HoldsCaPermission: false));

        Assert.DoesNotContain(options.Templates, t => t.TypeKey == "SubordinateCA");
        Assert.DoesNotContain(options.Purposes, p => p.Purpose == EnrollmentPurpose.SubordinateCa);
        Assert.Contains(options.Templates, t => t.TypeKey == "WebServer");
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task WithThePermissionOrAsAdmin_TheyAreOffered(bool ca, bool admin)
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);

        var options = await Options(scope, new CallerContext("s", "u", admin, ca));

        Assert.Contains(options.Templates, t => t.TypeKey == "SubordinateCA");
        Assert.Contains(options.Purposes, p => p.Purpose == EnrollmentPurpose.SubordinateCa);
    }

    [Fact]
    public async Task WithNoCaller_NothingIsFiltered()
    {
        await using var scope = await PolicyTestDb.CreateAsync(Ct);
        Assert.Contains((await Options(scope, null)).Templates, t => t.TypeKey == "SubordinateCA");
    }

    [Fact]
    public async Task Endpoint_HidesTheCaTemplateFromACreatorWithoutThePermission_ButNotFromAdmin()
    {
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, Ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "leaf-op", Permission = AppPermissions.CertificatesCreate });
            await db.SaveChangesAsync(Ct);
        }

        using var leaf = factory.CreateClient();
        leaf.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "leaf-op");
        var leafResponse = await leaf.GetAsync("/v1/enrollment/options", Ct);
        Assert.Equal(HttpStatusCode.OK, leafResponse.StatusCode);
        var leafOptions = (await leafResponse.Content.ReadFromJsonAsync<EnrollmentOptionsResponse>(Ct))!;
        Assert.DoesNotContain(leafOptions.Templates, t => t.TypeKey == "SubordinateCA");

        using var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        var adminOptions = (await admin.GetFromJsonAsync<EnrollmentOptionsResponse>("/v1/enrollment/options", Ct))!;
        Assert.Contains(adminOptions.Templates, t => t.TypeKey == "SubordinateCA");
    }
}
