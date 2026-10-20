using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

public sealed class IssuancePolicyApiTests
{
    private static HttpClient Admin(WebApplicationFactory<ApiServiceProgram> factory)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test");
        return client;
    }

    private static HttpClient AsRole(WebApplicationFactory<ApiServiceProgram> factory, string role)
    {
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Test-Role", role);
        return client;
    }

    private static async Task SeedRoleAsync(WebApplicationFactory<ApiServiceProgram> factory, string role,
        string[] permissions, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        db.RolePermissions.AddRange(permissions.Select(p => new RolePermission { Role = role, Permission = p }));
        await db.SaveChangesAsync(ct);
    }

    private static async Task<IssuancePolicyResponse> CreateWithDraftAsync(HttpClient client, string name,
        object draft, CancellationToken ct)
    {
        var created = await client.PostAsJsonAsync("/v1/issuance-policies", new { name }, ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var policy = (await created.Content.ReadFromJsonAsync<IssuancePolicyResponse>(ct))!;

        var saved = await client.PutAsJsonAsync($"/v1/issuance-policies/{policy.Id}/draft", draft, ct);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        return (await saved.Content.ReadFromJsonAsync<IssuancePolicyResponse>(ct))!;
    }

    private static Task<HttpResponseMessage> PublishAsync(HttpClient client, IssuancePolicyResponse policy, CancellationToken ct) =>
        client.PostAsJsonAsync($"/v1/issuance-policies/{policy.Id}/publish", new
        {
            draftVersionId = policy.Draft!.Id,
            draftUpdatedAtUtc = policy.Draft.UpdatedAtUtc
        }, ct);

    [Fact]
    public async Task Admin_CreatesDraftsAndPublishes()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);

        var policy = await CreateWithDraftAsync(admin, "corp", new { allowedDnsSuffixes = new[] { "corp.example.com" } }, ct);
        var published = await PublishAsync(admin, policy, ct);

        Assert.Equal(HttpStatusCode.OK, published.StatusCode);
        var body = (await published.Content.ReadFromJsonAsync<IssuancePolicyResponse>(ct))!;
        Assert.Equal(1, body.Published!.VersionNumber);
        Assert.Equal(["corp.example.com"], body.Published.AllowedDnsSuffixes);

        var list = await admin.GetFromJsonAsync<List<IssuancePolicySummaryResponse>>("/v1/issuance-policies", ct);
        Assert.Equal(1, Assert.Single(list!).PublishedVersionNumber);
    }

    [Fact]
    public async Task SettingsEditAlone_CanDraftButCannotPublish()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "drafters", [AppPermissions.SettingsEdit], ct);
        using var drafter = AsRole(factory, "drafters");

        var policy = await CreateWithDraftAsync(drafter, "corp", new { maxValidityDays = 90 }, ct);
        var publish = await PublishAsync(drafter, policy, ct);

        Assert.Equal(HttpStatusCode.Forbidden, publish.StatusCode);
    }

    [Fact]
    public async Task PoliciesPublishRole_CanPublish()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "publishers", [AppPermissions.PoliciesPublish], ct);
        using var admin = Admin(factory);
        using var publisher = AsRole(factory, "publishers");
        var policy = await CreateWithDraftAsync(admin, "corp", new { maxValidityDays = 90 }, ct);

        var publish = await PublishAsync(publisher, policy, ct);

        Assert.Equal(HttpStatusCode.OK, publish.StatusCode);
    }

    [Fact]
    public async Task CertificatesView_CanReadButNotCreate()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedRoleAsync(factory, "viewers", [AppPermissions.CertificatesView], ct);
        using var viewer = AsRole(factory, "viewers");

        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/v1/issuance-policies", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden,
            (await viewer.PostAsJsonAsync("/v1/issuance-policies", new { name = "nope" }, ct)).StatusCode);
    }

    [Fact]
    public async Task Publish_WithStaleDraftToken_Returns409()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var policy = await CreateWithDraftAsync(admin, "corp", new { maxValidityDays = 90 }, ct);

        var publish = await admin.PostAsJsonAsync($"/v1/issuance-policies/{policy.Id}/publish", new
        {
            draftVersionId = Guid.NewGuid(),
            draftUpdatedAtUtc = policy.Draft!.UpdatedAtUtc
        }, ct);

        Assert.Equal(HttpStatusCode.Conflict, publish.StatusCode);
    }

    [Fact]
    public async Task SaveDraft_WithWildcardSuffix_Returns400()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var created = await admin.PostAsJsonAsync("/v1/issuance-policies", new { name = "corp" }, ct);
        var policy = (await created.Content.ReadFromJsonAsync<IssuancePolicyResponse>(ct))!;

        var saved = await admin.PutAsJsonAsync($"/v1/issuance-policies/{policy.Id}/draft",
            new { allowedDnsSuffixes = new[] { "*.corp.example.com" } }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, saved.StatusCode);
    }

    [Fact]
    public async Task CreateCertificateRequest_OutsidePolicy_Returns400WithViolations()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", dnsSuffixes: ["corp.example.com"], name: "corp", ct: ct);
        }
        using var admin = Admin(factory);

        var response = await admin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = "host.other.net",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        Assert.Equal("corp", body.GetProperty("policyName").GetString());
        Assert.Equal(1, body.GetProperty("versionNumber").GetInt32());
        var violation = body.GetProperty("violations")[0];
        Assert.Equal("dnsSuffix", violation.GetProperty("rule").GetString());
        Assert.Equal("host.other.net", violation.GetProperty("value").GetString());
    }

    [Fact]
    public async Task Approve_AfterPolicyTightened_Returns422AndStaysPending()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var admin = Admin(factory);
        var createResponse = await admin.PostAsJsonAsync("/v1/certificate-requests", new
        {
            CommonName = "host.other.net",
            Type = "WebServer",
            PropertiesJson = "{}"
        }, ct);
        var created = (await createResponse.Content.ReadFromJsonAsync<CertificateRequest>(ct))!;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
        }

        var approve = await admin.PostAsync($"/v1/certificate-requests/{created.Id}/approve", null, ct);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, approve.StatusCode);
        using var verify = factory.Services.CreateScope();
        var stored = await verify.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == created.Id, ct);
        Assert.Equal(CertificateRequestStatus.Pending, stored.Status);
    }
}
