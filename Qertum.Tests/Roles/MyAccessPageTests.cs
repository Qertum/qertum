using System.Text;
using System.Text.Json;
using Bunit;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Roles;

public sealed class MyAccessPageTests
{
    private sealed class Stub(Func<HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(request.RequestUri!.AbsolutePath == "/v1/me/access" ? respond() : new HttpResponseMessage(HttpStatusCode.NotFound));
    }

    private static BunitContext Host(Func<HttpResponseMessage> respond)
    {
        var context = new BunitContext();
        context.AddAuthorization().SetAuthorized("alice");
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new Stub(respond)) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    private static HttpResponseMessage Json(MyAccessResponse value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
    };

    private static MyAccessResponse Access(bool isAdmin, params string[] granted) => new()
    {
        Roles = isAdmin ? ["admin"] : ["viewers"],
        IsAdmin = isAdmin,
        Permissions = AppPermissions.All.Select(p => new MyAccessPermission
        {
            Name = p, Description = AppPermissions.Descriptions[p], Granted = isAdmin || granted.Contains(p)
        }).ToList()
    };

    [Fact]
    public async Task NonAdmin_SeesCanAndCannotLists()
    {
        await using var context = Host(() => Json(Access(false, AppPermissions.CertificatesView)));
        var cut = context.Render<MyAccess>();

        cut.WaitForElement("[data-test='can']");
        Assert.Equal(["viewers"], cut.FindAll("[data-test='roles'] li").Select(li => li.TextContent.Trim()));
        Assert.Single(cut.FindAll("[data-test='can'] li"));
        Assert.Equal(AppPermissions.All.Count - 1, cut.FindAll("[data-test='cannot'] li").Count);
        Assert.Empty(cut.FindAll("[data-test='admin-banner']"));
    }

    [Fact]
    public async Task Admin_SeesBannerAndNoCannotList()
    {
        await using var context = Host(() => Json(Access(true)));
        var cut = context.Render<MyAccess>();

        cut.WaitForElement("[data-test='admin-banner']");
        Assert.Empty(cut.FindAll("[data-test='cannot'] li"));
    }

    [Fact]
    public async Task LoadFailure_ShowsUnavailable()
    {
        await using var context = Host(() => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var cut = context.Render<MyAccess>();

        cut.WaitForElement("[data-test='load-error']");
        Assert.Empty(cut.FindAll("[data-test='can']"));
    }
}
