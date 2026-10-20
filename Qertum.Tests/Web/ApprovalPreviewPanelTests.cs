using Microsoft.AspNetCore.Components;
using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

public sealed class ApprovalPreviewPanelTests
{
    private static readonly Guid V5 = Guid.NewGuid();

    private static CertificateRequest Pending() => new()
    {
        Id = Guid.NewGuid(), CommonName = "pending.example", Type = "WebServer", Status = CertificateRequestStatus.Pending
    };

    private static (BunitContext Context, DetailStub Api) NewContext(CertificateRequest request, ApprovalPreviewResponse preview, bool manage)
    {
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        context.Services.AddAutomationSnippets();
        var auth = context.AddAuthorization().SetAuthorized("alice");
        if (manage) auth.SetPolicies(AppPermissions.CertificatesManage);
        var api = new DetailStub(request, preview);
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        // The live circuit; the prerender test overrides this. Last, because it resolves the renderer.
        context.SetRendererInfo(new RendererInfo("Server", isInteractive: true));
        return (context, api);
    }

    [Fact]
    public async Task Panel_ShowsAdmittedVerdict()
    {
        var request = Pending();
        var (context, _) = NewContext(request, new ApprovalPreviewResponse { Allowed = true, PolicyName = "Web servers", PolicyVersionId = V5, PolicyVersionNumber = 5, EvaluatedPolicyVersionNumber = 5 }, manage: true);
        await using var _ctx = context;

        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));

        cut.WaitForAssertion(() => Assert.Equal("admitted", cut.Find("[data-test='approval-preview']").GetAttribute("data-state")));
        Assert.Contains("Web servers", cut.Find("[data-test='approval-preview']").TextContent);
        Assert.Contains("v5", cut.Find("[data-test='approval-preview']").TextContent);
        Assert.Empty(cut.FindAll("[data-test='approval-preview-changed']"));
    }

    [Fact]
    public async Task Panel_ShowsViolationsAndVersionChange()
    {
        var request = Pending();
        var (context, _) = NewContext(request, new ApprovalPreviewResponse
        {
            Allowed = false, PolicyName = "Web servers", PolicyVersionId = V5, PolicyVersionNumber = 5,
            EvaluatedPolicyVersionNumber = 3, EvaluatedPolicyName = "Legacy", PolicyChangedSinceEvaluation = true,
            Violations = [new IssuancePolicyViolation("dnsSuffix", "pending.example", "Name 'pending.example' is not under an allowed suffix.")]
        }, manage: true);
        await using var _ctx = context;

        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));

        cut.WaitForAssertion(() => Assert.Equal("refused", cut.Find("[data-test='approval-preview']").GetAttribute("data-state")));
        Assert.Contains("is not under an allowed suffix", cut.Markup);
        Assert.Contains("last evaluated under policy 'Legacy' v3", cut.Find("[data-test='approval-preview-changed']").TextContent);
    }

    [Fact]
    public async Task Panel_ShowsTheSelfApprovalRefusal()
    {
        var request = Pending();
        const string message = "You filed this request; a CA certificate must be approved by someone else.";
        var (context, _) = NewContext(request, new ApprovalPreviewResponse
        {
            Allowed = false, PolicyName = "CA", PolicyVersionId = V5, PolicyVersionNumber = 5, EvaluatedPolicyVersionNumber = 5,
            Violations = [new IssuancePolicyViolation("selfApproval", "alice", message)]
        }, manage: true);
        await using var _ctx = context;

        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));

        cut.WaitForAssertion(() => Assert.Equal("refused", cut.Find("[data-test='approval-preview']").GetAttribute("data-state")));
        Assert.Contains(message, cut.Find("[data-test='approval-preview']").TextContent);
    }

    [Fact]
    public async Task Panel_IsNotRenderedWithoutManagePermission()
    {
        var request = Pending();
        var (context, api) = NewContext(request, new ApprovalPreviewResponse { Allowed = true }, manage: false);
        await using var _ctx = context;

        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));

        cut.WaitForAssertion(() => Assert.Contains("pending.example", cut.Markup));
        Assert.Empty(cut.FindAll("[data-test='approval-preview']"));
        Assert.Equal(0, api.PreviewCalls);
    }

    [Fact]
    public async Task Prerender_DoesNotCallTheAuditedPreview()
    {
        // App.razor prerenders InteractiveServer pages: a load during prerender and another when the
        // circuit starts would write two ApprovalPreviewed entries for one look.
        var request = Pending();
        var (context, api) = NewContext(request, new ApprovalPreviewResponse { Allowed = true }, manage: true);
        await using var _ctx = context;
        context.SetRendererInfo(new RendererInfo("Static", isInteractive: false));

        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));

        cut.WaitForAssertion(() => Assert.Contains("pending.example", cut.Markup));
        Assert.Equal("loading", cut.Find("[data-test='approval-preview']").GetAttribute("data-state"));
        Assert.Equal(0, api.PreviewCalls);
    }

    [Fact]
    public async Task Approve_SendsTheDisplayedPreview()
    {
        var request = Pending();
        var (context, api) = NewContext(request, new ApprovalPreviewResponse { Allowed = true, PolicyName = "Web servers", PolicyVersionId = V5, PolicyVersionNumber = 5 }, manage: true);
        await using var _ctx = context;
        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));
        cut.WaitForAssertion(() => Assert.Equal("admitted", cut.Find("[data-test='approval-preview']").GetAttribute("data-state")));

        cut.Find("button.btn-success").Click();

        cut.WaitForAssertion(() => Assert.NotNull(api.ApproveBody));
        Assert.Equal(V5, api.ApproveBody!.PreviewedPolicyVersionId);
        Assert.True(api.ApproveBody.PreviewedAllowed);
    }

    [Fact]
    public async Task FailedApprove_ReloadsThePreview()
    {
        var request = Pending();
        var (context, api) = NewContext(request, new ApprovalPreviewResponse { Allowed = true, PolicyVersionId = V5, PolicyVersionNumber = 5, PolicyName = "Web servers" }, manage: true);
        api.RefuseApproval = true;
        await using var _ctx = context;
        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));
        cut.WaitForAssertion(() => Assert.Equal(1, api.PreviewCalls));

        cut.Find("button.btn-success").Click();

        cut.WaitForAssertion(() => Assert.Equal(2, api.PreviewCalls));
    }

    [Fact]
    public async Task ApproveWhilePreviewReloads_DoesNotReportTheOldVerdict()
    {
        var request = Pending();
        var (context, api) = NewContext(request, new ApprovalPreviewResponse
        {
            Allowed = true, PolicyVersionId = V5, PolicyVersionNumber = 5, PolicyName = "Web servers"
        }, manage: true);
        api.RefuseApproval = true;
        api.HeldPreview = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        await using var _ctx = context;
        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));
        cut.WaitForAssertion(() => Assert.Equal(1, api.PreviewCalls));

        var firstClick = cut.Find("button.btn-success").ClickAsync(new Microsoft.AspNetCore.Components.Web.MouseEventArgs());
        cut.WaitForAssertion(() => Assert.Equal(2, api.PreviewCalls));
        var secondClick = cut.Find("button.btn-success").ClickAsync(new Microsoft.AspNetCore.Components.Web.MouseEventArgs());

        cut.WaitForAssertion(() => Assert.Equal(2, api.ApproveBodies.Count));
        Assert.Null(api.ApproveBodies[1]);
        api.HeldPreview.SetResult(DetailStub.Json(api.Preview));
        await Task.WhenAll(firstClick, secondClick);
    }

    [Fact]
    public async Task OlderPreviewResponse_DoesNotReplaceTheNewerVerdict()
    {
        var request = Pending();
        var oldPreview = new ApprovalPreviewResponse { Allowed = false, PolicyName = "Old policy" };
        var newPreview = new ApprovalPreviewResponse { Allowed = true, PolicyName = "New policy" };
        var (context, api) = NewContext(request, oldPreview, manage: true);
        api.HeldFirstPreview = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        api.NextPreview = newPreview;
        await using var _ctx = context;
        var loaded = new List<ApprovalPreviewResponse?>();
        var cut = context.Render<ApprovalPreviewPanel>(p => p
            .Add(x => x.RequestId, (Guid)request.Id)
            .Add(x => x.RefreshKey, 0)
            .Add(x => x.OnLoaded, (ApprovalPreviewResponse? value) => loaded.Add(value)));
        cut.WaitForAssertion(() => Assert.Equal(1, api.PreviewCalls));

        cut.Render(p => p
            .Add(x => x.RequestId, (Guid)request.Id)
            .Add(x => x.RefreshKey, 1)
            .Add(x => x.OnLoaded, (ApprovalPreviewResponse? value) => loaded.Add(value)));
        cut.WaitForAssertion(() => Assert.Equal("admitted", cut.Find("[data-test='approval-preview']").GetAttribute("data-state")));
        api.HeldFirstPreview.SetResult(DetailStub.Json(oldPreview));
        await cut.InvokeAsync(async () => await Task.Yield());

        Assert.Equal("admitted", cut.Find("[data-test='approval-preview']").GetAttribute("data-state"));
        Assert.Single(loaded);
        Assert.Equal("New policy", loaded[0]?.PolicyName);
    }

    [Fact]
    public async Task ConflictingApprove_DoesNotReloadThePreview()
    {
        var request = Pending();
        var (context, api) = NewContext(request, new ApprovalPreviewResponse
        {
            Allowed = true, PolicyVersionId = V5, PolicyVersionNumber = 5, PolicyName = "Web servers"
        }, manage: true);
        api.ConflictApproval = true;
        await using var _ctx = context;
        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));
        cut.WaitForAssertion(() => Assert.Equal(1, api.PreviewCalls));

        cut.Find("button.btn-success").Click();

        cut.WaitForAssertion(() => Assert.Contains("already approved", cut.Markup));
        Assert.Equal(1, api.PreviewCalls);
        Assert.Equal("admitted", cut.Find("[data-test='approval-preview']").GetAttribute("data-state"));
    }

    private sealed class DetailStub(CertificateRequest request, ApprovalPreviewResponse preview) : HttpMessageHandler
    {
        public int PreviewCalls;
        public ApproveCertificateRequestRequest? ApproveBody;
        public List<ApproveCertificateRequestRequest?> ApproveBodies = [];
        public bool RefuseApproval;
        public bool ConflictApproval;
        public TaskCompletionSource<HttpResponseMessage>? HeldPreview;
        public TaskCompletionSource<HttpResponseMessage>? HeldFirstPreview;
        public ApprovalPreviewResponse? NextPreview;
        public ApprovalPreviewResponse Preview => preview;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage message, CancellationToken cancellationToken)
        {
            var path = message.RequestUri!.AbsolutePath;
            if (message.Method == HttpMethod.Get && path == $"/v1/certificate-requests/{request.Id}")
                return Json(request);
            if (message.Method == HttpMethod.Get && path == $"/v1/certificate-requests/{request.Id}/approval-preview")
            {
                var call = Interlocked.Increment(ref PreviewCalls);
                if (call == 1 && HeldFirstPreview is not null)
                    return await HeldFirstPreview.Task.WaitAsync(cancellationToken);
                if (PreviewCalls == 2 && HeldPreview is not null)
                    return await HeldPreview.Task.WaitAsync(cancellationToken);
                if (ConflictApproval && PreviewCalls > 1)
                    return new HttpResponseMessage(HttpStatusCode.Conflict)
                    {
                        Content = new StringContent("""{"title":"Conflict","status":409,"detail":"Request already approved."}""", Encoding.UTF8, "application/problem+json")
                    };
                return Json(call > 1 && NextPreview is not null ? NextPreview : preview);
            }
            if (message.Method == HttpMethod.Post && path == $"/v1/certificate-requests/{request.Id}/approve")
            {
                ApproveBody = message.Content is null
                    ? null
                    : JsonSerializer.Deserialize<ApproveCertificateRequestRequest>(await message.Content.ReadAsStringAsync(cancellationToken), JsonSerializerOptions.Web);
                ApproveBodies.Add(ApproveBody);
                if (ConflictApproval)
                    return new HttpResponseMessage(HttpStatusCode.Conflict)
                    {
                        Content = new StringContent("""{"title":"Conflict","status":409,"detail":"Request already approved."}""", Encoding.UTF8, "application/problem+json")
                    };
                if (RefuseApproval)
                    return new HttpResponseMessage(HttpStatusCode.UnprocessableEntity)
                    {
                        Content = new StringContent("""{"title":"Issuance policy violation","status":422,"detail":"refused","policyName":"Web servers","versionNumber":5,"violations":[{"rule":"dnsSuffix","value":"pending.example","message":"Name is not allowed."}]}""", Encoding.UTF8, "application/problem+json")
                    };
                return Json(new CertificateRequest { Id = request.Id, CommonName = request.CommonName, Type = request.Type, Status = CertificateRequestStatus.Approved });
            }
            // Everything else (timeline, etc.) answers 404, as CertificateRequestDetailNavigationTests' stub does.
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }

        public static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK)
        {
            Content = new StringContent(JsonSerializer.Serialize(value, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
        };
    }

    [Fact]
    public async Task Panel_SaysRequesterRolesAreCheckedAtSubmission()
    {
        var request = Pending();
        var (context, _) = NewContext(request, new ApprovalPreviewResponse
        {
            Allowed = true, PolicyName = "Web servers", PolicyVersionId = V5, PolicyVersionNumber = 5,
            RequesterRolesCheckedAtSubmission = true
        }, manage: true);
        await using var _ctx = context;

        var cut = context.Render<CertificateRequestDetail>(p => p.Add(x => x.Id, (Guid)request.Id));

        cut.WaitForAssertion(() => Assert.Equal("admitted", cut.Find("[data-test='approval-preview']").GetAttribute("data-state")));
        Assert.Contains("Requester roles are checked at submission, not at approval.",
            cut.Find("[data-test='approval-preview']").TextContent);
    }
}
