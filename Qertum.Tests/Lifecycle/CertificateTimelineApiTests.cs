using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Lifecycle;

namespace Qertum.Tests.Lifecycle;

public sealed class CertificateTimelineApiTests
{
    [Fact]
    public async Task Admin_GetsTheFullTimeline()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var id = await SeedIssuedRequestAsync(factory, ct);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");

        var response = await client.GetAsync($"/v1/certificate-requests/{id}/timeline", ct);
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync(ct);
        var timeline = await response.Content.ReadFromJsonAsync<CertificateTimelineResponse>(ct);

        Assert.Empty(timeline!.Withheld);
        Assert.Contains(timeline.Entries, e => e.Action == "PfxExported");
        // Enums travel by name.
        Assert.Contains("\"Record\"", json);
    }

    [Fact]
    public async Task Viewer_HasKeyExportsAndSettingsSectionsWithheld()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var id = await SeedIssuedRequestAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "viewer", Permission = AppPermissions.CertificatesView });
            await db.SaveChangesAsync(ct);
        }
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "viewer");

        var timeline = await client.GetFromJsonAsync<CertificateTimelineResponse>($"/v1/certificate-requests/{id}/timeline", ct);

        Assert.DoesNotContain(timeline!.Entries, e => e.Action == "PfxExported");
        Assert.Equal(
            [TimelineSection.WebhookDeliveries, TimelineSection.KeyExports, TimelineSection.Diagnostics],
            timeline.Withheld.Select(w => w.Section));
        Assert.Equal(1, timeline.Withheld.Single(w => w.Section == TimelineSection.KeyExports).Count);
    }

    [Fact]
    public async Task NoCertificatesView_Is403_AndUnknownId_Is404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        var id = await SeedIssuedRequestAsync(factory, ct);

        var noRole = factory.CreateClient();
        noRole.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-NoRole");
        Assert.Equal(HttpStatusCode.Forbidden,
            (await noRole.GetAsync($"/v1/certificate-requests/{id}/timeline", ct)).StatusCode);

        var admin = factory.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        Assert.Equal(HttpStatusCode.NotFound,
            (await admin.GetAsync($"/v1/certificate-requests/{Guid.NewGuid()}/timeline", ct)).StatusCode);
    }

    private static async Task<Guid> SeedIssuedRequestAsync(
        Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var request = new CertificateRequest
        {
            CommonName = "web.example.com", RequestedBy = "alice", RequestedBySubject = "sub-alice",
            Type = "WebServer", Status = CertificateRequestStatus.Issued,
            CreatedAtUtc = DateTime.UtcNow.AddDays(-1), UpdatedAtUtc = DateTime.UtcNow.AddDays(-1),
            ValidFrom = DateTime.UtcNow.AddDays(-1), ValidTo = DateTime.UtcNow.AddDays(89)
        };
        db.CertificateRequests.Add(request);
        db.LifecycleEvents.Add(new LifecycleEvent
        {
            Id = Guid.NewGuid(), Kind = LifecycleEventKinds.Audit, OccurredAtUtc = DateTime.UtcNow,
            SubjectType = LifecycleSubjectTypes.CertificateRequest, SubjectId = request.Id,
            Action = "PfxExported", PerformedBy = "alice"
        });
        await db.SaveChangesAsync(ct);
        return request.Id;
    }
}
