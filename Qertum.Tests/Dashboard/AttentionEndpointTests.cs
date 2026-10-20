using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Dashboard;

public sealed class AttentionEndpointTests
{
    private const string Route = "/v1/dashboard/attention";

    [Fact]
    public async Task WithoutAuth_Returns401()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);

        var response = await factory.CreateClient().GetAsync(Route, ct);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Admin_GetsAFullReportWithNothingWithheld()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var report = await client.GetFromJsonAsync<AttentionReport>(Route, ct);

        Assert.NotNull(report);
        Assert.Empty(report!.WithheldKinds);
    }

    [Fact]
    public async Task Viewer_GetsRequestKindsAndHasSettingsKindsWithheld()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "viewer", Permission = AppPermissions.CertificatesView });
            db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = "old.example.com", RequestedBy = "alice", Type = "WebServer",
                Status = CertificateRequestStatus.Pending,
                CreatedAtUtc = DateTime.UtcNow.AddDays(-10), UpdatedAtUtc = DateTime.UtcNow.AddDays(-10)
            });
            await db.SaveChangesAsync(ct);
        }
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "viewer");

        var response = await client.GetAsync(Route, ct);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync(ct);
        var report = await response.Content.ReadFromJsonAsync<AttentionReport>(ct);

        Assert.Contains(report!.Items, i => i.Kind == AttentionKind.AgingApprovals);
        Assert.Equal(
            [AttentionKind.FailedWebhookDeliveries, AttentionKind.DeltaCrlBase, AttentionKind.CaExpiry,
             AttentionKind.IssuerExpiring, AttentionKind.RootCrlExpiring, AttentionKind.IssuerArchivable, AttentionKind.IssuerRevoked,
             AttentionKind.PqcExceptionExpiring, AttentionKind.RecoveryStatus,
             AttentionKind.ApprovalsWaiting /* administrators only */],
            report.WithheldKinds);
        // Enums travel by name, not number.
        Assert.Contains("\"AgingApprovals\"", json);
        Assert.Contains("\"CaExpiry\"", json);
    }

    [Fact]
    public async Task NoRole_GetsEverythingWithheldRatherThan403()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = CreateFactory();
        await EnsureDbAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-NoRole");

        var report = await client.GetFromJsonAsync<AttentionReport>(Route, ct);

        Assert.Empty(report!.Items);
        Assert.Equal(Enum.GetValues<AttentionKind>(), report.WithheldKinds);
    }

    private static WebApplicationFactory<ApiServiceProgram> CreateFactory()
    {
        var database = SharedInMemoryDatabase.Create();
        return new WebApplicationFactory<ApiServiceProgram>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("ASPNETCORE_ENVIRONMENT", "Test");
            builder.ConfigureTestServices(services =>
            {
                database.ReplaceDbContext(services);

                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                }).AddScheme<Microsoft.AspNetCore.Authentication.AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });

                services.AddSingleton(StubCertificateGenerator.Returning(new CaStatusResponse()));
            });
        });
    }

    private static async Task EnsureDbAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await db.Database.OpenConnectionAsync(ct);
        await db.Database.EnsureCreatedAsync(ct);
    }
}
