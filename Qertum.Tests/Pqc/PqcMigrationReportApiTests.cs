using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Pqc;

public sealed class PqcMigrationReportApiTests
{
    private const string Route = "/v1/pqc/migration-report";

    private static HttpClient AsRole(WebApplicationFactory<ApiServiceProgram> factory, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", role);
        return client;
    }

    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static async Task GrantAsync(WebApplicationFactory<ApiServiceProgram> factory, string role, string permission, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.Add(new RolePermission { Role = role, Permission = permission });
        await db.SaveChangesAsync(ct);
    }

    private static async Task SeedAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var now = TimeProvider.System.GetUtcNow().UtcDateTime;
        var pending = new CertificateRequest
        {
            CommonName = "seen.corp.example", RequestedBy = "seed", Type = "WebServer", Status = CertificateRequestStatus.Pending,
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa
        };
        db.CertificateRequests.AddRange(pending, new CertificateRequest
        {
            CommonName = "live.corp.example", RequestedBy = "seed", Type = "WebServer", Status = CertificateRequestStatus.Issued,
            KeyAlgorithm = CertificateKeyAlgorithm.Rsa, ValidTo = now.AddDays(30), CertificatePem = ""
        });
        await db.SaveChangesAsync(ct);
        db.LifecycleEvents.Add(new LifecycleEvent
        {
            Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Diagnostic, SubjectType = LifecycleSubjectTypes.CertificateRequest,
            SubjectId = pending.Id, Action = PqcEventActions.Warned, PerformedBy = "alice", OccurredAtUtc = now.AddDays(-1)
        });
        await db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task Anonymous_IsUnauthorized()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateClient().GetAsync(Route, ct)).StatusCode);
    }

    [Fact]
    public async Task WithoutCertificatesView_IsForbidden()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await GrantAsync(factory, "creators", AppPermissions.CertificatesCreate, ct);

        Assert.Equal(HttpStatusCode.Forbidden, (await AsRole(factory, "creators").GetAsync(Route, ct)).StatusCode);
    }

    [Fact]
    public async Task AViewer_SeesLiveData_ButNotTheObservedBlock()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct);
        await GrantAsync(factory, "viewers", AppPermissions.CertificatesView, ct);

        var report = (await AsRole(factory, "viewers").GetFromJsonAsync<PqcMigrationReportResponse>($"{Route}?proposedStage=Enforce", ct))!;

        Assert.Equal(2, report.Items.TotalCount);
        Assert.Null(report.Observed);
        Assert.Equal(["observed"], report.Withheld);
    }

    [Fact]
    public async Task AnAdmin_SeesBoth()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct);

        var report = (await Admin(factory).GetFromJsonAsync<PqcMigrationReportResponse>(Route, ct))!;

        Assert.NotNull(report.Observed);
        Assert.Equal(1, report.Observed!.TotalEvents);
        Assert.Empty(report.Withheld);
    }

    [Theory]
    [InlineData("proposedStage=Sideways")]
    [InlineData("proposedStage=7")]
    [InlineData("observedDays=0")]
    [InlineData("observedDays=366")]
    [InlineData("page=0")]
    [InlineData("pageSize=0")]
    [InlineData("pageSize=501")]
    public async Task BadParameters_Are400Problems(string query)
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);

        var response = await Admin(factory).GetAsync($"{Route}?{query}", ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task AnUnknownTemplate_Is404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);

        var response = await Admin(factory).GetAsync($"{Route}?template=NoSuchTemplate", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task StageNamesAreCaseInsensitive_AndTheEnumSerializesAsAName()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct);

        var body = await Admin(factory).GetStringAsync($"{Route}?proposedStage=enforce", ct);

        Assert.Contains("\"proposedStage\":\"Enforce\"", body, StringComparison.Ordinal);
        Assert.Contains("\"verdict\":\"Refused\"", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCall_WritesNothing()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedAsync(factory, ct);
        async Task<(int, int, int, int)> CountsAsync()
        {
            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            return (await db.CertificateRequests.CountAsync(ct), await db.LifecycleEvents.CountAsync(ct),
                await db.WebhookDeliveries.CountAsync(ct), await db.Settings.CountAsync(ct));
        }
        var before = await CountsAsync();

        (await Admin(factory).GetAsync($"{Route}?proposedStage=Enforce", ct)).EnsureSuccessStatusCode();

        Assert.Equal(before, await CountsAsync());
    }
}
