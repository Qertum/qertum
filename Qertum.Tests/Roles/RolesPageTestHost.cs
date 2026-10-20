using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Bunit;
using Qertum.Services;

namespace Qertum.Tests.Roles;

internal sealed class RolesPageTestHost : IAsyncDisposable
{
    public RolesPageTestHost()
    {
        Context.AddAuthorization().SetAuthorized("alice").SetRoles("admin");
        Context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(Api) { BaseAddress = new Uri("http://api.test/") }));
    }

    public BunitContext Context { get; } = new();

    public RolesApiStub Api { get; } = new();

    public ValueTask DisposeAsync() => Context.DisposeAsync();
}

internal sealed class RolesApiStub : HttpMessageHandler
{
    private static readonly DateTime Now = new(2026, 9, 14, 12, 0, 0, DateTimeKind.Utc);

    public RolePermissionsOverviewResponse Overview { get; set; } = new()
    {
        Permissions = AppPermissions.All.Select(p => new PermissionInfo { Name = p, Description = AppPermissions.Descriptions[p] }).ToList(),
        Roles =
        [
            new RoleGrantSummary { Name = "ghost", Permissions = [AppPermissions.SettingsEdit], NeverSeen = true },
            new RoleGrantSummary { Name = "ops", Permissions = [AppPermissions.CertificatesView], FirstSeenUtc = Now.AddDays(-3), LastSeenUtc = Now.AddDays(-1) },
            new RoleGrantSummary { Name = "stale", Permissions = [AppPermissions.CertificatesManage], FirstSeenUtc = Now.AddDays(-60), LastSeenUtc = Now.AddDays(-40), NotSeenRecently = true }
        ],
        ObservedWithoutPermissions = [new ObservedRoleSummary { Name = "auditors", FirstSeenUtc = Now.AddDays(-2), LastSeenUtc = Now }],
        TrackingStartedUtc = Now.AddDays(-60),
        StaleAfterDays = 30
    };

    public bool FailOverview { get; set; }

    public string? PutProblemDetail { get; set; }

    public List<(string Role, IReadOnlyList<string> Permissions)> Puts { get; } = [];

    public List<(string Role, string NewRole)> Renames { get; } = [];

    public string? RenameProblemDetail { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;

        if (request.Method == HttpMethod.Get && path == "/v1/permissions/overview")
            return FailOverview ? Problem(HttpStatusCode.InternalServerError, "boom", null) : Json(Overview);

        if (request.Method == HttpMethod.Put && path.StartsWith("/v1/permissions/", StringComparison.Ordinal))
        {
            var role = Uri.UnescapeDataString(path["/v1/permissions/".Length..]);
            var body = (await request.Content!.ReadFromJsonAsync<SetRolePermissionsRequest>(cancellationToken))!;
            Puts.Add((role, body.Permissions));
            if (PutProblemDetail is not null)
                return Problem(HttpStatusCode.BadRequest, "Unknown permissions", PutProblemDetail);
            return Json(new RolePermissionChange(role, body.Permissions, []));
        }

        if (request.Method == HttpMethod.Post && path.EndsWith("/rename", StringComparison.Ordinal))
        {
            var role = Uri.UnescapeDataString(path["/v1/permissions/".Length..^"/rename".Length]);
            var body = (await request.Content!.ReadFromJsonAsync<RenameRoleRequest>(cancellationToken))!;
            Renames.Add((role, body.NewRole));
            return RenameProblemDetail is not null
                ? Problem(HttpStatusCode.Conflict, "Role already exists", RenameProblemDetail)
                : Json(new RoleRenameResponse(body.NewRole, role));
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
    };

    private static HttpResponseMessage Problem(HttpStatusCode status, string title, string? detail) => new(status)
    {
        Content = new StringContent(JsonSerializer.Serialize(new { title, detail }, JsonSerializerOptions.Web), Encoding.UTF8, "application/problem+json")
    };
}
