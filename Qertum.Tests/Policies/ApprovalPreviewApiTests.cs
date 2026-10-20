using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Policies;

public sealed class ApprovalPreviewApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static async Task<CertificateRequest> CreateAsync(HttpClient admin, string cn, CancellationToken ct)
    {
        var response = await admin.PostAsJsonAsync("/v1/certificate-requests",
            new { commonName = cn, type = "WebServer", propertiesJson = "{}" }, ct);
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<CertificateRequest>(ct))!;
    }

    [Fact]
    public async Task Preview_RefusedIsOkWithViolations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await CreateAsync(admin, "preview-refused.other.net", ct);
        using (var scope = factory.Services.CreateScope())
            await PolicySeeding.LinkPublishedPolicyAsync(
                scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>(), "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);

        var response = await admin.GetAsync($"/v1/certificate-requests/{created.Id}/approval-preview", ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = (await response.Content.ReadFromJsonAsync<ApprovalPreviewResponse>(ct))!;
        Assert.False(body.Allowed);
        Assert.NotEmpty(body.Violations);
        Assert.True(body.PolicyChangedSinceEvaluation);
    }

    [Fact]
    public async Task Preview_UnknownRequestIs404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.GetAsync($"/v1/certificate-requests/{Guid.NewGuid()}/approval-preview", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Preview_NotPendingIs409()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await CreateAsync(admin, "preview-approved.example", ct);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, ct)).StatusCode);

        var response = await admin.GetAsync($"/v1/certificate-requests/{created.Id}/approval-preview", ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task Preview_NeedsCertificatesManage()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await CreateAsync(admin, "preview-viewer.example", ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "viewer", Permission = AppPermissions.CertificatesView });
            await db.SaveChangesAsync(ct);
        }
        using var viewer = factory.CreateClient();
        viewer.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "viewer");

        var response = await viewer.GetAsync($"/v1/certificate-requests/{created.Id}/approval-preview", ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Approve_WithoutABody_StillApproves()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await CreateAsync(admin, "approve-nobody.example", ct);

        var response = await admin.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Approve_WithAPreviewReport_Approves()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await CreateAsync(admin, "approve-report.example", ct);

        var response = await admin.PostAsJsonAsync($"/v1/certificate-requests/{created.Id}/approve",
            new ApproveCertificateRequestRequest { PreviewedPolicyVersionId = null, PreviewedAllowed = true }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var scope = factory.Services.CreateScope();
        var stored = await scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(CertificateRequestStatus.Approved, stored.Status);
    }

    [Fact]
    public async Task ApiClient_ReadsTheRealPreviewResponse()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await CreateAsync(admin, "client-preview.example", ct);
        var client = new CertificateRequestsApiClient(admin);

        var preview = await client.PreviewApprovalAsync(created.Id, ct);

        Assert.NotNull(preview);
        Assert.True(preview!.Allowed);
    }
}
