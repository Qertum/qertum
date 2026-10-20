using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

/// <summary>
/// This is a post-quantum-first CA: onboarding proposes an ML-DSA root under stage Enforce, and a
/// classical root is a deliberate choice that needs the stage to allow it.
/// </summary>
public sealed class OnboardingPqcStageTests
{
    private sealed class Handler : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            lock (Requests) Requests.Add((request.Method, request.RequestUri!.AbsolutePath, body));
            if (request.Method == HttpMethod.Post && request.RequestUri.AbsolutePath == "/v1/ca/generate")
                return new HttpResponseMessage(HttpStatusCode.Created)
                {
                    Content = new StringContent($$"""{"id":"{{Guid.NewGuid()}}"}""", Encoding.UTF8, "application/json")
                };
            // The CA status call fails, which onboarding treats as "not configured yet".
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }
    }

    private static (BunitContext Context, Handler Api) NewContext(bool admin)
    {
        var handler = new Handler();
        var context = new BunitContext();
        var auth = context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.SettingsEdit);
        if (admin) auth.SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(handler) { BaseAddress = new Uri("http://api.test/") }));
        return (context, handler);
    }

    private static IRenderedComponent<Onboarding> OpenGenerateStep(BunitContext context)
    {
        var cut = context.Render<Onboarding>();
        cut.FindAll("button.option-card").Single(b => b.TextContent.Contains("Generate new CA", StringComparison.Ordinal)).Click();
        return cut;
    }

    private static AngleSharp.Dom.IElement GenerateButton(IRenderedComponent<Onboarding> cut) => cut.Find("button.ob-btn-submit");

    [Fact]
    public async Task TheRootDefaultsToMlDsa65_AndTheStageToEnforce()
    {
        var (context, _) = NewContext(admin: true);
        await using var _1 = context;
        var cut = OpenGenerateStep(context);

        Assert.Equal("ML-DSA-65", cut.Find("#gen-algo").GetAttribute("value"));
        Assert.Equal("Enforce", cut.Find("#gen-stage").GetAttribute("value"));
        Assert.False(GenerateButton(cut).HasAttribute("disabled"));
    }

    [Fact]
    public async Task AClassicalRootUnderEnforce_IsBlockedWithANote_UntilTheStageIsChanged()
    {
        var (context, _) = NewContext(admin: true);
        await using var _1 = context;
        var cut = OpenGenerateStep(context);

        cut.Find("#gen-algo").Change("RSA");
        Assert.NotEmpty(cut.FindAll("[data-test='ob-classical-root-blocked']"));
        Assert.True(GenerateButton(cut).HasAttribute("disabled"));

        cut.Find("#gen-stage").Change("Off");
        Assert.Empty(cut.FindAll("[data-test='ob-classical-root-blocked']"));
        Assert.False(GenerateButton(cut).HasAttribute("disabled"));
    }

    [Fact]
    public async Task ANonAdmin_CannotChangeTheStage_SoAClassicalRootStaysBlocked()
    {
        var (context, _) = NewContext(admin: false);
        await using var _1 = context;
        var cut = OpenGenerateStep(context);

        Assert.NotNull(cut.Find("#gen-stage").GetAttribute("disabled"));
        cut.Find("#gen-algo").Change("ECDSA-P384");

        Assert.True(GenerateButton(cut).HasAttribute("disabled"));
    }

    [Fact]
    public async Task Generate_SendsTheStageOnlyWhenItDiffersFromEnforce()
    {
        var (context, api) = NewContext(admin: true);
        await using var _1 = context;
        var cut = OpenGenerateStep(context);
        cut.Find("#gen-cn").Change("Test Root");
        cut.Find("button.ob-btn-submit").Click();

        cut.WaitForAssertion(() => Assert.Single(api.Requests, r => r.Path == "/v1/ca/generate"));
        using (var json = JsonDocument.Parse(api.Requests.Single(r => r.Path == "/v1/ca/generate").Body!))
            Assert.Equal(JsonValueKind.Null, json.RootElement.GetProperty("pqcStage").ValueKind);

        var (context2, api2) = NewContext(admin: true);
        await using var _2 = context2;
        var cut2 = OpenGenerateStep(context2);
        cut2.Find("#gen-cn").Change("Test Root");
        cut2.Find("#gen-algo").Change("RSA");
        cut2.Find("#gen-stage").Change("Off");
        cut2.Find("button.ob-btn-submit").Click();

        cut2.WaitForAssertion(() => Assert.Single(api2.Requests, r => r.Path == "/v1/ca/generate"));
        using var json2 = JsonDocument.Parse(api2.Requests.Single(r => r.Path == "/v1/ca/generate").Body!);
        Assert.Equal("Off", json2.RootElement.GetProperty("pqcStage").GetString());
    }
}
