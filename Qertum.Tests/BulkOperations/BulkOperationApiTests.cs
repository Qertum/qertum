using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Mvc.Testing;
using Qertum.Services;

namespace Qertum.Tests.BulkOperations;

public sealed class BulkOperationApiTests
{
    private const string Route = "/v1/bulk-operations";
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private static async Task SeedIssuedAsync(WebApplicationFactory<ApiServiceProgram> factory, int count, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        for (var i = 0; i < count; i++)
            db.CertificateRequests.Add(new CertificateRequest
            {
                CommonName = $"bulk{i}.contoso.local", RequestedBy = "seed", Status = CertificateRequestStatus.Issued,
                ValidFrom = DateTime.UtcNow.AddDays(-1), ValidTo = DateTime.UtcNow.AddDays(200),
                CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow
            });
        await db.SaveChangesAsync(ct);
    }

    private static Task<HttpResponseMessage> PreviewAsync(HttpClient client, string kind, object filter, string? reason, CancellationToken ct) =>
        client.PostAsJsonAsync($"{Route}/preview", new { kind, filter, reason }, ct);

    [Fact]
    public async Task Preview_AsAdmin_Returns201WithTheOperationAndALocation()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 2, ct);
        using var client = Admin(factory);

        using var response = await PreviewAsync(client, "Revoke", new { all = true }, "compromised", ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var preview = await response.Content.ReadFromJsonAsync<BulkOperationPreview>(Web, ct);
        Assert.Equal(2, preview!.Operation.ItemCount);
        Assert.Equal(BulkOperationStatus.Previewed, preview.Operation.Status);
        Assert.Equal($"{Route}/{preview.Operation.Id}", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Preview_EmptyFilter_Returns422Problem_WithTraceId()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var client = Admin(factory);

        using var response = await PreviewAsync(client, "Revoke", new { }, "x", ct);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(ct));
        Assert.Equal(422, body.RootElement.GetProperty("status").GetInt32());
        Assert.True(body.RootElement.TryGetProperty("traceId", out _));
    }

    [Fact]
    public async Task Preview_UsesThePermissionOfTheKind()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 1, ct);
        await SeedRoleAsync(factory, "creator", [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate], ct);
        await SeedRoleAsync(factory, "manager", [AppPermissions.CertificatesView, AppPermissions.CertificatesManage], ct);

        using var creator = AsRole(factory, "creator");
        using var manager = AsRole(factory, "manager");

        Assert.Equal(HttpStatusCode.Forbidden, (await PreviewAsync(creator, "Revoke", new { all = true }, "x", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await PreviewAsync(creator, "Renew", new { all = true }, null, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PreviewAsync(manager, "Renew", new { all = true }, null, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await PreviewAsync(manager, "Revoke", new { all = true }, "x", ct)).StatusCode);
    }

    [Fact]
    public async Task Execute_WrongCount_Returns409_RightCount_Returns202WithRetryAfter()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 2, ct);
        using var client = Admin(factory);
        var preview = await (await PreviewAsync(client, "Revoke", new { all = true }, "x", ct))
            .Content.ReadFromJsonAsync<BulkOperationPreview>(Web, ct);
        var id = preview!.Operation.Id;

        using var wrong = await client.PostAsJsonAsync($"{Route}/{id}/execute", new { confirmCount = 1 }, ct);
        Assert.Equal(HttpStatusCode.Conflict, wrong.StatusCode);

        using var right = await client.PostAsJsonAsync($"{Route}/{id}/execute", new { confirmCount = 2 }, ct);
        Assert.Equal(HttpStatusCode.Accepted, right.StatusCode);
        Assert.Equal("2", right.Headers.GetValues("Retry-After").Single());

        using var again = await client.PostAsJsonAsync($"{Route}/{id}/execute", new { confirmCount = 2 }, ct);
        Assert.Equal(HttpStatusCode.Conflict, again.StatusCode);
    }

    [Fact]
    public async Task Routes_RejectAnonymousCallers()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var anonymous = factory.CreateClient();

        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(Route, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync($"{Route}/preview", new { }, ct)).StatusCode);
    }

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

    private static async Task<BulkOperationId> PreviewIdAsync(HttpClient client, string kind, CancellationToken ct)
    {
        using var response = await PreviewAsync(client, kind, new { all = true }, kind == "Revoke" ? "x" : null, ct);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<BulkOperationPreview>(Web, ct))!.Operation.Id;
    }

    private static async Task UpdateOperationAsync(WebApplicationFactory<ApiServiceProgram> factory, BulkOperationId id,
        Action<BulkOperation> change, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        var operation = await db.BulkOperations.SingleAsync(o => o.Id == id, ct);
        change(operation);
        await db.SaveChangesAsync(ct);
    }

    [Fact]
    public async Task Get_WhileRunning_SendsRetryAfter_AndAfterCompletionDoesNot()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 1, ct);
        using var client = Admin(factory);
        var id = await PreviewIdAsync(client, "Revoke", ct);
        (await client.PostAsJsonAsync($"{Route}/{id}/execute", new { confirmCount = 1 }, ct)).EnsureSuccessStatusCode();

        using var running = await client.GetAsync($"{Route}/{id}", ct);
        Assert.Equal("2", running.Headers.GetValues("Retry-After").Single());

        await UpdateOperationAsync(factory, id, o => o.Status = BulkOperationStatus.Completed, ct);
        using var done = await client.GetAsync($"{Route}/{id}", ct);
        Assert.False(done.Headers.Contains("Retry-After"));
    }

    [Fact]
    public async Task Get_UnknownId_Returns404Problem()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        using var client = Admin(factory);

        using var response = await client.GetAsync($"{Route}/{Guid.NewGuid()}", ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType!.MediaType);
    }

    [Fact]
    public async Task Items_PagedAndFilteredByOutcome()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 2, ct);
        using var client = Admin(factory);
        var id = await PreviewIdAsync(client, "Revoke", ct);

        var pending = await client.GetFromJsonAsync<PagedResult<BulkOperationItemView>>($"{Route}/{id}/items?outcome=Pending&pageSize=1", Web, ct);
        var done = await client.GetFromJsonAsync<PagedResult<BulkOperationItemView>>($"{Route}/{id}/items?outcome=Done", Web, ct);

        Assert.Equal(2, pending!.TotalCount);
        Assert.Single(pending.Items);
        Assert.Equal(0, done!.TotalCount);
    }

    [Fact]
    public async Task List_NonAdminSeesOnlyOwn_AdminSeesAll()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 1, ct);
        await SeedRoleAsync(factory, "mgrA", [AppPermissions.CertificatesView, AppPermissions.CertificatesManage], ct);
        await SeedRoleAsync(factory, "mgrB", [AppPermissions.CertificatesView, AppPermissions.CertificatesManage], ct);
        using var a = AsRole(factory, "mgrA");
        using var b = AsRole(factory, "mgrB");
        using var admin = Admin(factory);
        await PreviewIdAsync(a, "Revoke", ct);
        await PreviewIdAsync(admin, "Revoke", ct);

        Assert.Equal(1, (await a.GetFromJsonAsync<PagedResult<BulkOperationView>>(Route, Web, ct))!.TotalCount);
        Assert.Equal(0, (await b.GetFromJsonAsync<PagedResult<BulkOperationView>>(Route, Web, ct))!.TotalCount);
        Assert.Equal(2, (await admin.GetFromJsonAsync<PagedResult<BulkOperationView>>(Route, Web, ct))!.TotalCount);
    }

    [Fact]
    public async Task Get_AnotherUsersOperation_Returns404ForANonAdmin_ButNotForAnAdmin()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 1, ct);
        await SeedRoleAsync(factory, "mgrA", [AppPermissions.CertificatesView, AppPermissions.CertificatesManage], ct);
        await SeedRoleAsync(factory, "mgrB", [AppPermissions.CertificatesView, AppPermissions.CertificatesManage], ct);
        using var a = AsRole(factory, "mgrA");
        using var b = AsRole(factory, "mgrB");
        using var admin = Admin(factory);
        var id = await PreviewIdAsync(a, "Revoke", ct);

        Assert.Equal(HttpStatusCode.NotFound, (await b.GetAsync($"{Route}/{id}", ct)).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await b.PostAsync($"{Route}/{id}/cancel", null, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.GetAsync($"{Route}/{id}", ct)).StatusCode);
    }

    [Fact]
    public async Task Cancel_Previewed_Returns200_ThenExecuteIs409()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 1, ct);
        using var client = Admin(factory);
        var id = await PreviewIdAsync(client, "Revoke", ct);

        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync($"{Route}/{id}/cancel", null, ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await client.PostAsJsonAsync($"{Route}/{id}/execute", new { confirmCount = 1 }, ct)).StatusCode);
    }

    [Fact]
    public async Task Execute_AfterThePreviewTtl_Returns410()
    {
        var ct = TestContext.Current.CancellationToken;
        await using var factory = ApiServiceTests.CreateFactory();
        await ApiServiceTests.EnsureDbAsync(factory, ct);
        await SeedIssuedAsync(factory, 1, ct);
        using var client = Admin(factory);
        var id = await PreviewIdAsync(client, "Revoke", ct);
        await UpdateOperationAsync(factory, id, o => o.CreatedAtUtc = DateTime.UtcNow.AddHours(-2), ct);

        using var response = await client.PostAsJsonAsync($"{Route}/{id}/execute", new { confirmCount = 1 }, ct);

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
    }
}
