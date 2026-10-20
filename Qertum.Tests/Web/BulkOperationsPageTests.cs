using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using BulkPage = Qertum.Web.Components.Pages.BulkOperations;

namespace Qertum.Tests.Web;

public sealed class BulkOperationsPageTests
{
    private static readonly Guid OperationGuid = Guid.Parse("44444444-4444-4444-4444-444444444444");

    private static string Operation(string status, int items = 3, int done = 0, int failed = 0, string kind = "Revoke") =>
        $$"""{"id":"{{OperationGuid}}","kind":"{{kind}}","status":"{{status}}","itemCount":{{items}},"doneCount":{{done}},"skippedCount":0,"failedCount":{{failed}},"createdBy":"alice","filter":{"all":true},"excluded":{"not-issued":4,"active-renewal":1} }""";

    /// <summary>Answers the bulk routes with canned JSON and records every request.</summary>
    private sealed class BulkApiStub : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];
        public string FinalOperation { get; set; } = Operation("Completed", done: 3);
        public string Kind { get; set; } = "Revoke";
        public string? PreviewRefusal { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            var path = request.RequestUri!.AbsolutePath;
            Requests.Add((request.Method, path, body));

            (HttpStatusCode, string) answer = path switch
            {
                "/v1/bulk-operations/preview" when PreviewRefusal is not null => (HttpStatusCode.UnprocessableEntity,
                    $$"""{"title":"Unprocessable Entity","status":422,"detail":"{{PreviewRefusal}}"}"""),
                "/v1/bulk-operations/preview" => (HttpStatusCode.Created,
                    $$"""{"operation":{{Operation("Previewed", kind: Kind)}},"sample":[{"requestId":"{{Guid.NewGuid()}}","commonName":"a.example","outcome":"Pending"},{"requestId":"{{Guid.NewGuid()}}","commonName":"b.example","outcome":"Pending"}]}"""),
                var p when p.EndsWith("/execute") => (HttpStatusCode.Accepted, Operation("Running", kind: Kind)),
                var p when p.EndsWith("/cancel") => (HttpStatusCode.OK, Operation("Cancelled", kind: Kind)),
                var p when p.EndsWith("/items") => (HttpStatusCode.OK,
                    $$"""{"items":[{"requestId":"{{Guid.NewGuid()}}","commonName":"broken.example","outcome":"Failed","detail":"Blocked by issuance policy"}],"totalCount":1,"page":1,"pageSize":100}"""),
                var p when p.StartsWith("/v1/bulk-operations/") => (HttpStatusCode.OK, FinalOperation),
                _ => (HttpStatusCode.OK, "[]")
            };
            return new HttpResponseMessage(answer.Item1) { Content = new StringContent(answer.Item2, Encoding.UTF8, "application/json") };
        }
    }

    private static (BunitContext Context, BulkApiStub Api) NewContext(params string[] permissions)
    {
        var api = new BulkApiStub();
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();
        var auth = context.AddAuthorization().SetAuthorized("alice");
        auth.SetPolicies(permissions);
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        return (context, api);
    }

    private static readonly TimeSpan Patience = TimeSpan.FromSeconds(5);

    [Fact]
    public void ThePage_IsForAnySignedInUser_TheApiDecidesThePermissionPerKind()
    {
        var attribute = Assert.Single(typeof(BulkPage).GetCustomAttributes(typeof(AuthorizeAttribute), inherit: true).Cast<AuthorizeAttribute>());
        Assert.Null(attribute.Policy);
        Assert.Null(attribute.Roles);
    }

    [Fact]
    public async Task Kinds_AreOfferedOnlyForThePermissionsHeld()
    {
        var (manager, _) = NewContext(AppPermissions.CertificatesManage);
        await using var _1 = manager;
        var cut = manager.Render<BulkPage>();
        Assert.NotEmpty(cut.FindAll("[data-test='kind-revoke']"));
        Assert.Empty(cut.FindAll("[data-test='kind-renew']"));

        var (creator, _) = NewContext(AppPermissions.CertificatesCreate);
        await using var _2 = creator;
        var cut2 = creator.Render<BulkPage>();
        Assert.Empty(cut2.FindAll("[data-test='kind-revoke']"));
        Assert.NotEmpty(cut2.FindAll("[data-test='kind-renew']"));
    }

    [Fact]
    public async Task Preview_StartsDisabled_AndNeedsAKind_AFilterMode_AndForRevokeAReason()
    {
        var (context, _) = NewContext(AppPermissions.CertificatesManage, AppPermissions.CertificatesCreate);
        await using var _ = context;
        var cut = context.Render<BulkPage>();
        Assert.True(cut.Find("[data-test='preview-button']").HasAttribute("disabled"));

        cut.Find("[data-test='kind-revoke']").Change(true);
        cut.Find("[data-test='mode-all']").Change(true);
        Assert.True(cut.Find("[data-test='preview-button']").HasAttribute("disabled")); // revoke needs a reason

        cut.Find("[data-test='reason']").Input("key compromise");
        Assert.False(cut.Find("[data-test='preview-button']").HasAttribute("disabled"));

        cut.Find("[data-test='reason']").Input("");
        Assert.True(cut.Find("[data-test='preview-button']").HasAttribute("disabled"));
        cut.Find("[data-test='kind-renew']").Change(true);
        Assert.False(cut.Find("[data-test='preview-button']").HasAttribute("disabled")); // renew needs no reason
    }

    [Fact]
    public async Task CriteriaMode_NeedsAtLeastOneCriterion()
    {
        var (context, _) = NewContext(AppPermissions.CertificatesCreate);
        await using var _ = context;
        var cut = context.Render<BulkPage>();
        cut.Find("[data-test='kind-renew']").Change(true);
        cut.Find("[data-test='mode-criteria']").Change(true);
        Assert.True(cut.Find("[data-test='preview-button']").HasAttribute("disabled"));

        cut.Find("[data-test='criterion-cn']").Input("example");
        Assert.False(cut.Find("[data-test='preview-button']").HasAttribute("disabled"));
    }

    [Fact]
    public async Task Preview_ShowsTheCount_TheExclusionsInPlainLanguage_AndTheSample()
    {
        var (context, api) = NewContext(AppPermissions.CertificatesManage);
        await using var _ = context;
        var cut = context.Render<BulkPage>();
        cut.Find("[data-test='kind-revoke']").Change(true);
        cut.Find("[data-test='mode-all']").Change(true);
        cut.Find("[data-test='reason']").Input("key compromise");

        cut.Find("[data-test='preview-button']").Click();

        cut.WaitForAssertion(() => Assert.Equal("3", cut.Find("[data-test='preview-count']").TextContent.Trim()), Patience);
        Assert.Contains("not issued", cut.Find("[data-test='excluded-not-issued']").TextContent);
        Assert.Contains("already has a renewal", cut.Find("[data-test='excluded-active-renewal']").TextContent);
        Assert.Equal(2, cut.FindAll("[data-test='sample-row']").Count);
        var preview = api.Requests.Single(r => r.Path.EndsWith("/preview"));
        using var json = JsonDocument.Parse(preview.Body!);
        Assert.True(json.RootElement.GetProperty("filter").GetProperty("all").GetBoolean());
        Assert.Equal("key compromise", json.RootElement.GetProperty("reason").GetString());
    }

    [Fact]
    public async Task Confirm_StaysDisabledUntilTheExactCountIsTyped_ThenExecutesAndShowsTheResult()
    {
        var (context, api) = NewContext(AppPermissions.CertificatesManage);
        await using var _ = context;
        var cut = context.Render<BulkPage>();
        cut.Find("[data-test='kind-revoke']").Change(true);
        cut.Find("[data-test='mode-all']").Change(true);
        cut.Find("[data-test='reason']").Input("key compromise");
        cut.Find("[data-test='preview-button']").Click();
        cut.WaitForElement("[data-test='continue']", Patience).Click();

        Assert.True(cut.Find("[data-test='bulk-apply']").HasAttribute("disabled"));
        cut.Find("[data-test='confirm-input']").Input("2");
        Assert.True(cut.Find("[data-test='bulk-apply']").HasAttribute("disabled"));
        cut.Find("[data-test='confirm-input']").Input("3");
        Assert.False(cut.Find("[data-test='bulk-apply']").HasAttribute("disabled"));

        cut.Find("[data-test='bulk-apply']").Click();

        cut.WaitForAssertion(() => Assert.Contains("Completed", cut.Find("[data-test='final-status']").TextContent), Patience);
        var execute = api.Requests.Single(r => r.Path.EndsWith("/execute"));
        Assert.Equal("""{"confirmCount":3}""", execute.Body);
    }

    [Fact]
    public async Task FailedItems_AreListedWithTheirReason()
    {
        var (context, api) = NewContext(AppPermissions.CertificatesCreate);
        await using var _ = context;
        api.Kind = "Renew";
        api.FinalOperation = Operation("CompletedWithErrors", done: 2, failed: 1, kind: "Renew");
        var cut = context.Render<BulkPage>();
        cut.Find("[data-test='kind-renew']").Change(true);
        cut.Find("[data-test='mode-all']").Change(true);
        cut.Find("[data-test='preview-button']").Click();
        cut.WaitForElement("[data-test='continue']", Patience).Click();
        cut.Find("[data-test='confirm-input']").Input("3");
        cut.Find("[data-test='bulk-apply']").Click();

        cut.WaitForAssertion(() => Assert.Contains("broken.example", cut.Find("[data-test='failed-row']").TextContent), Patience);
        Assert.Contains("Blocked by issuance policy", cut.Find("[data-test='failed-row']").TextContent);
    }

    [Fact]
    public async Task Back_FromThePreview_CancelsIt()
    {
        var (context, api) = NewContext(AppPermissions.CertificatesManage);
        await using var _ = context;
        var cut = context.Render<BulkPage>();
        cut.Find("[data-test='kind-revoke']").Change(true);
        cut.Find("[data-test='mode-all']").Change(true);
        cut.Find("[data-test='reason']").Input("r");
        cut.Find("[data-test='preview-button']").Click();

        cut.WaitForElement("[data-test='back']", Patience).Click();

        cut.WaitForAssertion(() => Assert.Contains(api.Requests, r => r.Path.EndsWith("/cancel")), Patience);
        cut.WaitForElement("[data-test='preview-button']", Patience);
    }

    [Fact]
    public async Task APreviewTheServerRefuses_ShowsTheReason_AndStaysOnTheFirstStep()
    {
        var (context, api) = NewContext(AppPermissions.CertificatesManage);
        await using var _ = context;
        api.PreviewRefusal = "No eligible certificate matches the filter.";
        var cut = context.Render<BulkPage>();
        cut.Find("[data-test='kind-revoke']").Change(true);
        cut.Find("[data-test='mode-all']").Change(true);
        cut.Find("[data-test='reason']").Input("r");

        cut.Find("[data-test='preview-button']").Click();

        cut.WaitForAssertion(() => Assert.Contains("No eligible certificate matches the filter.", cut.Find("[data-test='page-error']").TextContent), Patience);
        Assert.Empty(cut.FindAll("[data-test='preview-count']"));
        Assert.NotEmpty(cut.FindAll("[data-test='preview-button']"));
    }

    [Fact]
    public async Task TheEntryOnTheCertificatesList_IsShownOnlyWithAPermission()
    {
        var (without, _) = NewContext();
        await using var _1 = without;
        Assert.Empty(without.Render<Qertum.Web.Components.Pages.Certificates>().FindAll("[data-test='bulk-actions']"));

        var (with, _) = NewContext(AppPermissions.CertificatesManage);
        await using var _2 = with;
        Assert.NotEmpty(with.Render<Qertum.Web.Components.Pages.Certificates>().FindAll("[data-test='bulk-actions']"));
    }
}
