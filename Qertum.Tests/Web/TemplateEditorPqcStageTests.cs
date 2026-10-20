using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class TemplateEditorPqcStageTests
{
    private static readonly CertificateTemplateId TemplateId = new(Guid.NewGuid());
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private static (BunitContext Context, IssuerApiStub Api) NewContext(bool admin, PqcStage? current = null, PqcStage caDefault = PqcStage.Enforce)
    {
        var api = new IssuerApiStub();
        var template = new CertificateTemplate { Id = TemplateId, Name = "Web", TypeKey = "WebServer", PqcStageOverride = current };
        var templatePath = $"/v1/certificate-templates/{TemplateId}";
        api.Override = r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            object? payload = path == templatePath || path == templatePath + "/pqc-stage" ? template
                : path == "/v1/settings" ? new CaSettings { PqcStage = caDefault }
                : null;
            return payload is null ? null : new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload, Web), System.Text.Encoding.UTF8, "application/json")
            };
        };
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        var auth = context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.SettingsEdit, AppPermissions.PoliciesPublish);
        if (admin) auth.SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        return (context, api);
    }

    private static IRenderedComponent<TemplateEditor> RenderAtLastStep(BunitContext context)
    {
        var cut = context.Render<TemplateEditor>(p => p.Add(x => x.Id, (Guid)TemplateId));
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='template-next'], [data-test='template-save']")));
        while (cut.FindAll("[data-test='template-save']").Count == 0)
            cut.Find("[data-test='template-next']").Click();
        return cut;
    }

    [Fact]
    public async Task Admin_SeesTheOverrideSelect_WithTheCaDefaultNamed()
    {
        var (context, _) = NewContext(admin: true, caDefault: PqcStage.Warn);
        await using var _1 = context;

        var cut = RenderAtLastStep(context);

        cut.WaitForAssertion(() => Assert.Equal(
            ["", .. Enum.GetNames<PqcStage>()], cut.FindAll("#pqc-stage-override option").Select(o => o.GetAttribute("value"))));
        Assert.Equal("CA default (Warn)", cut.FindAll("#pqc-stage-override option")[0].TextContent.Trim());
    }

    [Fact]
    public async Task NonAdmin_DoesNotSeeTheOverrideSelect()
    {
        var (context, _) = NewContext(admin: false);
        await using var _1 = context;

        var cut = RenderAtLastStep(context);

        Assert.Empty(cut.FindAll("#pqc-stage-override"));
    }

    [Fact]
    public async Task APreviewLink_CarriesTheTemplateAndTheChosenStage()
    {
        var (context, _) = NewContext(admin: true);
        await using var _1 = context;
        var cut = RenderAtLastStep(context);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("a[data-test='template-preview-impact']")));

        Assert.Equal("pqc-migration?template=WebServer", cut.Find("a[data-test='template-preview-impact']").GetAttribute("href"));

        cut.Find("#pqc-stage-override").Change("Warn");

        Assert.Equal("pqc-migration?template=WebServer&proposedStage=Warn",
            cut.Find("a[data-test='template-preview-impact']").GetAttribute("href"));
    }

    [Fact]
    public async Task SavingWithoutChangingTheOverride_DoesNotCallTheStageEndpoint()
    {
        var (context, api) = NewContext(admin: true);
        await using var _1 = context;
        var cut = RenderAtLastStep(context);

        cut.Find("[data-test='template-save']").Click();

        cut.WaitForAssertion(() => Assert.Contains(api.Requests, r => r.Method == HttpMethod.Put));
        Assert.DoesNotContain(api.Requests, r => r.Path.EndsWith("/pqc-stage", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ChangingTheOverride_CallsPutStageOnce()
    {
        var (context, api) = NewContext(admin: true);
        await using var _1 = context;
        var cut = RenderAtLastStep(context);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#pqc-stage-override")));

        cut.Find("#pqc-stage-override").Change("Warn");
        cut.Find("[data-test='template-save']").Click();

        cut.WaitForAssertion(() =>
        {
            var call = Assert.Single(api.Requests, r => r.Path == $"/v1/certificate-templates/{TemplateId}/pqc-stage");
            Assert.Equal("""{"stage":"Warn"}""", call.Body);
        });
    }

    [Fact]
    public async Task ClearingTheOverride_SendsNull()
    {
        var (context, api) = NewContext(admin: true, current: PqcStage.Pilot);
        await using var _1 = context;
        var cut = RenderAtLastStep(context);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("#pqc-stage-override")));

        cut.Find("#pqc-stage-override").Change("");
        cut.Find("[data-test='template-save']").Click();

        cut.WaitForAssertion(() =>
            Assert.Equal("""{"stage":null}""", Assert.Single(api.Requests, r => r.Path.EndsWith("/pqc-stage", StringComparison.Ordinal)).Body));
    }
}
