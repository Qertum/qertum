using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class TemplateEditorIssuerTests
{
    private static readonly CertificateTemplateId TemplateId = new(Guid.NewGuid());

    private static (BunitContext Context, IssuerApiStub Api) NewContext(IssuerId? pinned = null)
    {
        var api = new IssuerApiStub();
        var template = new CertificateTemplate { Id = TemplateId, Name = "Web", TypeKey = "WebServer", IssuerId = pinned };
        var templatePath = $"/v1/certificate-templates/{TemplateId}";
        api.Override = r => r.RequestUri!.AbsolutePath == templatePath || r.RequestUri.AbsolutePath == templatePath + "/issuer"
            ? new HttpResponseMessage(System.Net.HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(template, new JsonSerializerOptions(JsonSerializerDefaults.Web)),
                    System.Text.Encoding.UTF8, "application/json")
            }
            : null;
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.SettingsEdit, AppPermissions.PoliciesPublish);
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        return (context, api);
    }

    [Fact]
    public async Task IssuerDropdown_ListsDefaultAndActiveOnlineIssuersOnly()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var active = IssuerApiStub.Issuer("Active Online");
        api.Issuers.AddRange([active, IssuerApiStub.Issuer("Retired", status: IssuerStatus.Retired),
            IssuerApiStub.Issuer("Offline", custody: IssuerKeyCustody.Offline),
            IssuerApiStub.Issuer("Pending", status: IssuerStatus.PendingCertificate)]);

        var cut = context.Render<TemplateEditor>(p => p.Add(x => x.Id, (Guid)TemplateId));
        GoToLastStep(cut);

        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("#template-issuer option").Count));
        Assert.Equal(["", active.Id.ToString()], cut.FindAll("#template-issuer option").Select(o => o.GetAttribute("value")));
    }

    [Fact]
    public async Task APinToAnIssuerThatCannotIssue_IsKeptAsTheCurrentChoice()
    {
        var (context, _) = NewContext(pinned: new IssuerId(Guid.NewGuid()));
        await using var __ = context;

        var cut = context.Render<TemplateEditor>(p => p.Add(x => x.Id, (Guid)TemplateId));
        GoToLastStep(cut);

        cut.WaitForAssertion(() => Assert.Contains(cut.FindAll("#template-issuer option"), o => o.TextContent.Contains("cannot issue")));
    }

    [Fact]
    public async Task SavingWithoutChangingTheIssuer_DoesNotCallTheIssuerEndpoint()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var cut = context.Render<TemplateEditor>(p => p.Add(x => x.Id, (Guid)TemplateId));
        GoToLastStep(cut);

        cut.Find("[data-test='template-save']").Click();

        cut.WaitForAssertion(() => Assert.Contains(api.Requests, r => r.Method == HttpMethod.Put));
        Assert.DoesNotContain(api.Requests, r => r.Path.EndsWith("/issuer", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ChangingTheIssuer_CallsPutIssuerOnce()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var target = IssuerApiStub.Issuer("Target");
        api.Issuers.Add(target);
        var cut = context.Render<TemplateEditor>(p => p.Add(x => x.Id, (Guid)TemplateId));
        GoToLastStep(cut);
        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("#template-issuer option").Count));

        cut.Find("#template-issuer").Change(target.Id.ToString());
        cut.Find("[data-test='template-save']").Click();

        cut.WaitForAssertion(() => Assert.Single(api.Requests, r => r.Path == $"/v1/certificate-templates/{TemplateId}/issuer"));
        Assert.Contains(target.Id.ToString(), api.Requests.Single(r => r.Path.EndsWith("/issuer", StringComparison.Ordinal)).Body);
    }

    /// <summary>The editor is a wizard; the issuer select and the save button are on its last step.</summary>
    private static void GoToLastStep(IRenderedComponent<TemplateEditor> cut)
    {
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='template-next'], [data-test='template-save']")));
        while (cut.FindAll("[data-test='template-save']").Count == 0)
            cut.Find("[data-test='template-next']").Click();
    }
}
