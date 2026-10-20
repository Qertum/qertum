using System.Net;
using System.Text;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;
using Qertum.Web.Components.Shared;

namespace Qertum.Tests.Web;

public sealed class ApprovalsPageTests
{
    private sealed class Api(Func<HttpRequestMessage, string?, HttpResponseMessage> answer) : HttpMessageHandler
    {
        public List<(HttpMethod Method, string Path, string? Body)> Calls { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            lock (Calls) Calls.Add((request.Method, request.RequestUri!.PathAndQuery, body));
            return answer(request, body);
        }
    }

    private static string Item(string id, string status, bool mine, string requester = "alice") => $$"""
        {"id":"{{id}}","operation":"bulk-revoke","targetId":"3f1d9c0e-0000-4000-8000-000000000001","targetLabel":"bulk revoke of 12 certificates",
         "note":"cleanup","requestedByName":"{{requester}}","requestedAtUtc":"2026-10-18T10:00:00Z","status":"{{status}}","isMine":{{(mine ? "true" : "false")}},
         "decidedByName":null,"decidedAtUtc":null,"decisionNote":null,"grantExpiresAtUtc":null,"usedAtUtc":null}
        """;

    private const string Mine = "11111111-1111-1111-1111-111111111111";
    private const string Theirs = "22222222-2222-2222-2222-222222222222";

    private static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK, string? correlationId = null)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (correlationId is not null) response.Headers.TryAddWithoutValidation("X-Correlation-Id", correlationId);
        return response;
    }

    private static (IRenderedComponent<ApprovalQueue> Cut, Api Handler) Render(Func<HttpRequestMessage, string?, HttpResponseMessage> answer, bool admin)
    {
        var handler = new Api(answer);
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        var auth = context.AddAuthorization().SetAuthorized("alice");
        if (admin) auth.SetRoles("admin");
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(handler) { BaseAddress = new Uri("http://api.test/") }));
        return (context.Render<ApprovalQueue>(), handler);
    }

    private static HttpResponseMessage List(HttpRequestMessage request, string? body) =>
        Json($$"""{"items":[{{Item(Mine, "Pending", mine: true)}},{{Item(Theirs, "Pending", mine: false, requester: "bob")}}],"totalCount":2,"page":1,"pageSize":50}""");

    [Fact]
    public void ListsTheApprovals_WithOperationTargetStatusAndRequester()
    {
        var (cut, _) = Render(List, admin: false);

        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("[data-test='approval-row']").Count));
        var row = cut.FindAll("[data-test='approval-row']")[1].TextContent;
        Assert.Contains("bulk-revoke", row);
        Assert.Contains("bulk revoke of 12 certificates", row);
        Assert.Contains("Pending", row);
        Assert.Contains("bob", row);
    }

    [Fact]
    public void AnAdmin_GetsDecisionButtonsOnOthersPendingRows_NotOnTheirOwn()
    {
        var (cut, _) = Render(List, admin: true);

        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("[data-test='approval-row']").Count));
        Assert.Empty(cut.FindAll($"[data-test='approve-{Mine}']"));
        Assert.NotEmpty(cut.FindAll($"[data-test='approve-{Theirs}']"));
        Assert.NotEmpty(cut.FindAll($"[data-test='deny-{Theirs}']"));
    }

    [Fact]
    public void ANonAdmin_GetsNoDecisionButtons()
    {
        var (cut, _) = Render(List, admin: false);

        cut.WaitForAssertion(() => Assert.Equal(2, cut.FindAll("[data-test='approval-row']").Count));
        Assert.Empty(cut.FindAll("[data-test^='approve-']"));
        Assert.Empty(cut.FindAll("[data-test^='deny-']"));
    }

    [Fact]
    public void Approving_PostsTheRoute_AndReloads()
    {
        var (cut, handler) = Render((request, body) => request.Method == HttpMethod.Post
            ? Json(Item(Theirs, "Approved", mine: false, requester: "bob"))
            : List(request, body), admin: true);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll($"[data-test='approve-{Theirs}']")));

        cut.Find($"[data-test='approve-{Theirs}']").Click();

        cut.WaitForAssertion(() => Assert.Contains(handler.Calls, c => c.Method == HttpMethod.Post && c.Path == $"/v1/approvals/{Theirs}/approve"));
        cut.WaitForAssertion(() => Assert.True(handler.Calls.Count(c => c.Method == HttpMethod.Get) >= 2));
    }

    [Fact]
    public void Denying_PostsTheRoute()
    {
        var (cut, handler) = Render((request, body) => request.Method == HttpMethod.Post
            ? Json(Item(Theirs, "Denied", mine: false, requester: "bob"))
            : List(request, body), admin: true);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll($"[data-test='deny-{Theirs}']")));

        cut.Find($"[data-test='deny-{Theirs}']").Click();

        cut.WaitForAssertion(() => Assert.Contains(handler.Calls, c => c.Method == HttpMethod.Post && c.Path == $"/v1/approvals/{Theirs}/deny"));
    }

    [Fact]
    public void TheRequestForm_PostsTheOperationTargetAndNote()
    {
        var (cut, handler) = Render((request, body) => request.Method == HttpMethod.Post
            ? Json(Item(Mine, "Pending", mine: true))
            : List(request, body), admin: false);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='request-operation']")));

        cut.Find("[data-test='request-operation']").Change("bulk-revoke");
        cut.Find("[data-test='request-target']").Input("3f1d9c0e-0000-4000-8000-000000000001");
        cut.Find("[data-test='request-note']").Input("cleanup");
        cut.Find("[data-test='request-submit']").Click();

        cut.WaitForAssertion(() =>
        {
            var post = Assert.Single(handler.Calls, c => c.Method == HttpMethod.Post);
            Assert.Equal("/v1/approvals", post.Path);
            Assert.Contains("\"operation\":\"bulk-revoke\"", post.Body);
            Assert.Contains("\"targetId\":\"3f1d9c0e-0000-4000-8000-000000000001\"", post.Body);
            Assert.Contains("\"note\":\"cleanup\"", post.Body);
        });
    }

    [Fact]
    public void AFailedDecision_ShowsTheProblemWithItsCorrelationId()
    {
        var (cut, _) = Render((request, body) => request.Method == HttpMethod.Post
            ? Json("""{"title":"Conflict","detail":"The request is no longer pending."}""", HttpStatusCode.Conflict, "abc123def456")
            : List(request, body), admin: true);
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll($"[data-test='approve-{Theirs}']")));

        cut.Find($"[data-test='approve-{Theirs}']").Click();

        cut.WaitForAssertion(() =>
        {
            var text = cut.Find("[data-test='approvals-error']").TextContent;
            Assert.Contains("no longer pending", text);
            Assert.Contains("(correlation id: abc123def456)", text);
        });
    }

    [Fact]
    public void WithNothingToShow_ShowsAnEmptyState()
    {
        var (cut, _) = Render((_, _) => Json("""{"items":[],"totalCount":0,"page":1,"pageSize":50}"""), admin: false);

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='approvals-empty']")));
    }

    [Fact]
    public void AnApprovalRequiredRefusal_IsExplainedWithWhereToAsk()
    {
        var refusal = new ApiProblemException(HttpStatusCode.Forbidden, "Approval required", "A second administrator must approve.", null, null, [],
            approval: new ApprovalChallenge("bulk-revoke", "abc"));

        Assert.Contains("Approvals page", refusal.WithCorrelationId("Failed: " + refusal.Message), StringComparison.Ordinal);
        Assert.DoesNotContain("Approvals page", new Exception("x").WithCorrelationId("Failed: x"), StringComparison.Ordinal);
    }
}
