using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Tests.Policies;

namespace Qertum.Tests.Pqc;

public sealed class PqcExceptionApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static async Task<HttpClient> SettingsEditorAsync(WebApplicationFactory<ApiServiceProgram> factory, CancellationToken ct)
    {
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.RolePermissions.Add(new RolePermission { Role = "editor", Permission = AppPermissions.SettingsEdit });
            await db.SaveChangesAsync(ct);
        }
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", "editor");
        return client;
    }

    private static object Body(string pattern = "legacy.corp.example", string template = "WebServer", int days = 30) => new
    {
        templateTypeKey = template, namePattern = pattern, family = "Rsa",
        expiresAtUtc = TimeProvider.System.GetUtcNow().UtcDateTime.AddDays(days), reason = "old load balancer"
    };

    [Fact]
    public async Task NonAdmin_WithSettingsEdit_IsForbiddenOnReadsAndWrites()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var editor = await SettingsEditorAsync(factory, ct);

        Assert.Equal(HttpStatusCode.Forbidden, (await editor.GetAsync("/v1/pqc-exceptions", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await editor.PostAsJsonAsync("/v1/pqc-exceptions", Body(), ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await editor.PostAsync($"/v1/pqc-exceptions/{Guid.NewGuid()}/revoke", null, ct)).StatusCode);
    }

    [Fact]
    public async Task Admin_CreatesAnException_WhichIsActiveAndAttributed()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/pqc-exceptions", Body(), ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = (await response.Content.ReadFromJsonAsync<PqcExceptionResponse>(ct))!;
        Assert.True(created.IsActive);
        Assert.False(string.IsNullOrWhiteSpace(created.GrantedBy));
        Assert.Equal("legacy.corp.example", created.NamePattern);
    }

    [Fact]
    public async Task UnknownTemplate_Is404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/pqc-exceptions", Body(template: "NoSuchTemplate"), ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Contains("Template 'NoSuchTemplate' does not exist.", await response.Content.ReadAsStringAsync(ct));
    }

    [Fact]
    public async Task InvalidBody_Is400WithValidationErrors()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/pqc-exceptions", Body(pattern: "*.corp.example"), ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task List_OmitsRevokedAndExpired_UnlessAsked()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var active = (await (await admin.PostAsJsonAsync("/v1/pqc-exceptions", Body("active.corp.example"), ct))
            .Content.ReadFromJsonAsync<PqcExceptionResponse>(ct))!;
        var revoked = (await (await admin.PostAsJsonAsync("/v1/pqc-exceptions", Body("revoked.corp.example"), ct))
            .Content.ReadFromJsonAsync<PqcExceptionResponse>(ct))!;
        (await admin.PostAsync($"/v1/pqc-exceptions/{revoked.Id}/revoke", null, ct)).EnsureSuccessStatusCode();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var now = TimeProvider.System.GetUtcNow().UtcDateTime;
            db.PqcExceptions.Add(new PqcException
            {
                TemplateTypeKey = "WebServer", NamePattern = "expired.corp.example", Family = PqcExceptionFamily.Rsa,
                ExpiresAtUtc = now.AddDays(-1), Reason = "gone", GrantedBy = "admin", CreatedAtUtc = now.AddDays(-10)
            });
            await db.SaveChangesAsync(ct);
        }

        var defaults = (await admin.GetFromJsonAsync<List<PqcExceptionResponse>>("/v1/pqc-exceptions", ct))!;
        var everything = (await admin.GetFromJsonAsync<List<PqcExceptionResponse>>("/v1/pqc-exceptions?includeInactive=true", ct))!;

        Assert.Equal([active.Id], defaults.Select(e => e.Id));
        Assert.Equal(3, everything.Count);
    }

    [Fact]
    public async Task Revoke_SetsTheTimestamp_ASecondRevokeIs409_AndAnUnknownIdIs404()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = (await (await admin.PostAsJsonAsync("/v1/pqc-exceptions", Body(), ct))
            .Content.ReadFromJsonAsync<PqcExceptionResponse>(ct))!;

        var first = await admin.PostAsync($"/v1/pqc-exceptions/{created.Id}/revoke", null, ct);
        var second = await admin.PostAsync($"/v1/pqc-exceptions/{created.Id}/revoke", null, ct);
        var unknown = await admin.PostAsync($"/v1/pqc-exceptions/{Guid.NewGuid()}/revoke", null, ct);

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        var revoked = (await first.Content.ReadFromJsonAsync<PqcExceptionResponse>(ct))!;
        Assert.NotNull(revoked.RevokedAtUtc);
        Assert.False(revoked.IsActive);
        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
    }

    [Fact]
    public async Task CreateAndRevoke_AreAuditedAndQueueAWebhook()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var scope = await PolicyTestDb.CreateAsync(ct);
        scope.Db.Webhooks.Add(new Webhook
        {
            Name = "settings", Url = "https://hooks.example/settings", Family = WebhookEventFamily.Settings,
            EventsJson = "[]", IsEnabled = true
        });
        await scope.Db.SaveChangesAsync(ct);
        var service = new PqcExceptionService(scope.Db, scope.Audit, scope.CreateWebhookService());
        var now = TimeProvider.System.GetUtcNow().UtcDateTime;

        var created = await service.CreateAsync(new CreatePqcExceptionRequest
        {
            TemplateTypeKey = "WebServer", NamePattern = "Legacy.Corp.Example.", Family = PqcExceptionFamily.Rsa,
            ExpiresAtUtc = now.AddDays(10), Reason = "old load balancer"
        }, "alice", "sub-alice", ct);
        await service.RevokeAsync(created.Id, "bob", ct);

        Assert.Equal("legacy.corp.example", created.NamePattern);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "PqcExceptionCreated" && e.PerformedBy == "alice"
            && e.ResourceId == (Guid)created.Id);
        Assert.Contains(scope.Audit.Entries, e => e.Action == "PqcExceptionRevoked" && e.PerformedBy == "bob");
        var deliveries = await scope.Db.WebhookDeliveries.AsNoTracking().Select(d => d.EventType).ToListAsync(ct);
        Assert.Contains(WellKnownWebhookEvents.PqcExceptionCreated, deliveries);
        Assert.Contains(WellKnownWebhookEvents.PqcExceptionRevoked, deliveries);
    }

    [Fact]
    public async Task AtEnforce_AnExceptionAdmitsItsName_ButNotAnotherName()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        (await admin.PutAsJsonAsync("/v1/settings/pqc-stage", new { stage = "Enforce" }, ct)).EnsureSuccessStatusCode();
        static object Request(string cn) => new { CommonName = cn, RequestedBy = "t", Type = "WebServer", PropertiesJson = "{}" };

        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PostAsJsonAsync("/v1/certificate-requests", Request("legacy.corp.example"), ct)).StatusCode);

        (await admin.PostAsJsonAsync("/v1/pqc-exceptions", Body(), ct)).EnsureSuccessStatusCode();

        var allowed = await admin.PostAsJsonAsync("/v1/certificate-requests", Request("legacy.corp.example"), ct);
        Assert.Equal(HttpStatusCode.Created, allowed.StatusCode);
        using var json = JsonDocument.Parse(await allowed.Content.ReadAsStringAsync(ct));
        Assert.Equal(JsonValueKind.Array, json.RootElement.GetProperty("warnings").ValueKind);

        Assert.Equal(HttpStatusCode.BadRequest,
            (await admin.PostAsJsonAsync("/v1/certificate-requests", Request("other.corp.example"), ct)).StatusCode);
    }
}
