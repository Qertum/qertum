using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;

namespace Qertum.Tests;

public sealed class CertificateMetadataApiTests
{
    private sealed class Arranged(WebApplicationFactory<ApiServiceProgram> factory, Guid requestId) : IAsyncDisposable
    {
        public Guid RequestId { get; } = requestId;
        public WebApplicationFactory<ApiServiceProgram> Factory { get; } = factory;

        /// <summary>Admin when <paramref name="role"/> is null; otherwise a non-admin with subject "sub-{role}".</summary>
        public HttpClient As(string? role)
        {
            var client = Factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = role is null
                ? new AuthenticationHeaderValue("Test")
                : new AuthenticationHeaderValue("Test-Role", role);
            return client;
        }

        public ValueTask DisposeAsync() => Factory.DisposeAsync();
    }

    // Roles: owner/viewer = certificates.view, manager = view + manage, creator = create only.
    // The seeded request is owned by subject "sub-owner" unless a legacy null subject is asked for.
    private static async Task<Arranged> ArrangeAsync(string? subject = "sub-owner")
    {
        var ct = TestContext.Current.CancellationToken;
        var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(
            new RolePermission { Role = "owner", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "viewer", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "manager", Permission = AppPermissions.CertificatesView },
            new RolePermission { Role = "manager", Permission = AppPermissions.CertificatesManage },
            new RolePermission { Role = "creator", Permission = AppPermissions.CertificatesCreate });
        var request = new CertificateRequest
        {
            CommonName = "meta.contoso.local", RequestedBy = "Alice", RequestedBySubject = subject,
            Type = "WebServer", Status = CertificateRequestStatus.Issued
        };
        db.CertificateRequests.Add(request);
        await db.SaveChangesAsync(ct);
        return new Arranged(factory, request.Id.Value);
    }

    private static string Url(Guid id) => $"/v1/certificate-requests/{id}/metadata";

    private static async Task<CertificateMetadata> StoredAsync(Arranged arranged)
    {
        using var admin = arranged.As(null);
        var request = await admin.GetFromJsonAsync<CertificateRequest>(
            $"/v1/certificate-requests/{arranged.RequestId}", TestContext.Current.CancellationToken);
        return request!.Metadata;
    }

    [Fact]
    public async Task Put_AsAdmin_StoresTheSet_AndTheDetailReturnsIt()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var response = await admin.PutAsJsonAsync(Url(arranged.RequestId),
            new CertificateMetadata { OwnerTeam = "Platform", ContactEmail = "ops@contoso.local" }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var stored = await StoredAsync(arranged);
        Assert.Equal("Platform", stored.OwnerTeam);
        Assert.Equal("ops@contoso.local", stored.ContactEmail);
    }

    [Fact]
    public async Task Put_AsTheOwner_Succeeds()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var owner = arranged.As("owner");

        var response = await owner.PutAsJsonAsync(Url(arranged.RequestId), new CertificateMetadata { Purpose = "api" }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("api", (await StoredAsync(arranged)).Purpose);
    }

    [Fact]
    public async Task Put_WithCertificatesManage_Succeeds()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var manager = arranged.As("manager");

        var response = await manager.PutAsJsonAsync(Url(arranged.RequestId), new CertificateMetadata { TargetSystem = "gw" }, ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Put_AsAnotherViewer_IsForbidden_AndChangesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var viewer = arranged.As("viewer");

        var response = await viewer.PutAsJsonAsync(Url(arranged.RequestId), new CertificateMetadata { OwnerTeam = "Mallory" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null((await StoredAsync(arranged)).OwnerTeam);
    }

    [Fact]
    public async Task Put_OnALegacyNullSubjectRow_NeedsManageOrAdmin()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync(subject: null);
        using var owner = arranged.As("owner");
        using var manager = arranged.As("manager");

        var asViewer = await owner.PutAsJsonAsync(Url(arranged.RequestId), new CertificateMetadata { Purpose = "x" }, ct);
        var asManager = await manager.PutAsJsonAsync(Url(arranged.RequestId), new CertificateMetadata { Purpose = "x" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, asViewer.StatusCode);
        Assert.Equal(HttpStatusCode.OK, asManager.StatusCode);
    }

    [Fact]
    public async Task Put_UnknownId_Is404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var response = await admin.PutAsJsonAsync(Url(Guid.NewGuid()), new CertificateMetadata(), ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Put_ByAStranger_OnAnUnknownId_Is404_NotAValidationError()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var viewer = arranged.As("viewer");

        var response = await viewer.PutAsJsonAsync(Url(Guid.NewGuid()),
            new CertificateMetadata { OwnerTeam = new string('a', 101) }, ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Put_ByAStranger_WithAnInvalidBody_Is403_BeforeValidation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var viewer = arranged.As("viewer");

        var response = await viewer.PutAsJsonAsync(Url(arranged.RequestId),
            new CertificateMetadata { OwnerTeam = new string('a', 101) }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_InvalidBody_Is400_NamingEachField()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var response = await admin.PutAsJsonAsync(Url(arranged.RequestId),
            new CertificateMetadata { OwnerTeam = new string('a', 101), ContactEmail = "not-an-email" }, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("OwnerTeam", body, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("ContactEmail", body, StringComparison.OrdinalIgnoreCase);
        Assert.Null((await StoredAsync(arranged)).OwnerTeam);
    }

    [Fact]
    public async Task Put_KeyMaterialInAField_Is400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var response = await admin.PutAsJsonAsync(Url(arranged.RequestId),
            new CertificateMetadata { Purpose = "-----BEGIN PRIVATE KEY-----" }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Put_WithoutCertificatesView_Is403()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var creator = arranged.As("creator");

        var response = await creator.PutAsJsonAsync(Url(arranged.RequestId), new CertificateMetadata { Purpose = "x" }, ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task Put_DoesNotChangeTheRequester()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var manager = arranged.As("manager");
        using var admin = arranged.As(null);

        await manager.PutAsJsonAsync(Url(arranged.RequestId), new CertificateMetadata { OwnerTeam = "x" }, ct);
        var request = await admin.GetFromJsonAsync<CertificateRequest>($"/v1/certificate-requests/{arranged.RequestId}", ct);

        Assert.Equal("Alice", request!.RequestedBy);
        Assert.Equal("sub-owner", request.RequestedBySubject);
    }

    [Fact]
    public async Task Create_WithMetadata_StoresIt_AndInvalidMetadataIs400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var arranged = await ArrangeAsync();
        using var admin = arranged.As(null);

        var created = await admin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = "with-meta.contoso.local", Type = "WebServer", PropertiesJson = "{}",
            Metadata = new { OwnerTeam = "Platform", TicketReference = "OPS-1" }
        }, ct);
        var request = await created.Content.ReadFromJsonAsync<CertificateRequest>(ct);
        var rejected = await admin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = "bad-meta.contoso.local", Type = "WebServer", PropertiesJson = "{}",
            Metadata = new { ContactEmail = "nope" }
        }, ct);

        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        Assert.Equal("Platform", request!.Metadata.OwnerTeam);
        Assert.Equal("OPS-1", request.Metadata.TicketReference);
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
    }
}
