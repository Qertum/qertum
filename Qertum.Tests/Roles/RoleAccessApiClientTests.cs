using System.Net.Http.Headers;
using Qertum.Services;

namespace Qertum.Tests.Roles;

public sealed class RoleAccessApiClientTests
{
    [Fact]
    public async Task Client_RoundTripsAndSurfacesProblems()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var http = factory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        var client = new CertificateRequestsApiClient(http);

        var change = await client.SetRolePermissionsAsync("ops team", [AppPermissions.CertificatesView], ct);
        Assert.Equal("ops team", change.Role);

        var overview = await client.GetRolePermissionsOverviewAsync(ct);
        Assert.Equal("ops team", Assert.Single(overview.Roles).Name);

        var me = await client.GetMyAccessAsync(ct);
        Assert.True(me.IsAdmin);

        var problem = await Assert.ThrowsAsync<ApiProblemException>(() =>
            client.SetRolePermissionsAsync("ops", ["nope"], ct));
        Assert.Equal(HttpStatusCode.BadRequest, problem.StatusCode);
        Assert.Contains("nope", problem.Detail);
    }
}
