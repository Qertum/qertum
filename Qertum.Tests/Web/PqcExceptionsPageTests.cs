using System.Net;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class PqcExceptionsPageTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 29, 12, 0, 0, TimeSpan.Zero);
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private sealed class Stub : HttpMessageHandler
    {
        public List<PqcExceptionResponse> Exceptions { get; } = [];
        public List<(HttpMethod Method, string PathAndQuery, string? Body)> Requests { get; } = [];
        public HttpResponseMessage? CreateReply { get; set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            lock (Requests) Requests.Add((request.Method, request.RequestUri!.PathAndQuery, body));
            var path = request.RequestUri.AbsolutePath;
            if (request.Method == HttpMethod.Post && path == "/v1/pqc-exceptions" && CreateReply is not null) return CreateReply;
            object? payload = path switch
            {
                "/v1/pqc-exceptions" when request.Method == HttpMethod.Get =>
                    request.RequestUri.Query.Contains("includeInactive=true") ? Exceptions : Exceptions.Where(e => e.IsActive).ToList(),
                "/v1/certificate-templates" => new[]
                {
                    new CertificateTemplate { Name = "Web Server", TypeKey = "WebServer" },
                    new CertificateTemplate { Name = "Client", TypeKey = "ClientAuth" }
                },
                _ when path.EndsWith("/revoke", StringComparison.Ordinal) => Exceptions.First(),
                _ => new { }
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonSerializer.Serialize(payload, Web), Encoding.UTF8, "application/json")
            };
        }
    }

    private static PqcExceptionResponse Exception(string name, bool active = true, bool revoked = false) => new()
    {
        Id = new PqcExceptionId(Guid.NewGuid()), TemplateTypeKey = "WebServer", NamePattern = name,
        Family = PqcExceptionFamily.Rsa, ExpiresAtUtc = Now.UtcDateTime.AddDays(active ? 30 : -1), Reason = "old load balancer",
        GrantedBy = "alice", CreatedAtUtc = Now.UtcDateTime.AddDays(-5),
        RevokedAtUtc = revoked ? Now.UtcDateTime.AddDays(-1) : null, RevokedBy = revoked ? "bob" : null,
        IsActive = active && !revoked
    };

    private static (BunitContext Context, Stub Api) NewContext()
    {
        var api = new Stub();
        var context = new BunitContext();
        context.Services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        context.AddAuthorization().SetAuthorized("alice").SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        return (context, api);
    }

    private static IRenderedComponent<PqcExceptions> Render(BunitContext context)
    {
        var cut = context.Render<PqcExceptions>();
        cut.WaitForElement("#pqc-name");
        return cut;
    }

    private static void FillValid(IRenderedComponent<PqcExceptions> cut)
    {
        cut.Find("#pqc-name").Input("legacy.corp.example");
        cut.Find("#pqc-days").Input("30");
        cut.Find("#pqc-reason").Input("old load balancer");
    }

    [Fact]
    public void ThePageRequiresTheAdminRole()
    {
        var attribute = Assert.Single(typeof(PqcExceptions)
            .GetCustomAttributes(typeof(Microsoft.AspNetCore.Authorization.AuthorizeAttribute), inherit: true)
            .Cast<Microsoft.AspNetCore.Authorization.AuthorizeAttribute>());
        Assert.Equal("admin", attribute.Roles);
    }

    [Fact]
    public async Task ListsActiveExceptions_WithTheirFacts()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var active = Exception("legacy.corp.example");
        api.Exceptions.AddRange([active, Exception("old.corp.example", active: false)]);

        var cut = context.Render<PqcExceptions>();

        var row = cut.WaitForElement($"tr[data-exception='{active.Id}']");
        Assert.Contains("legacy.corp.example", row.TextContent);
        Assert.Contains("WebServer", row.TextContent);
        Assert.Contains("old load balancer", row.TextContent);
        Assert.Contains("alice", row.TextContent);
        Assert.Contains("2026-10-29", row.TextContent);
        Assert.Single(cut.FindAll("tr[data-exception]"));
    }

    [Fact]
    public async Task ShowInactive_AsksForEverything()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.Exceptions.AddRange([Exception("legacy.corp.example"), Exception("old.corp.example", active: false),
            Exception("revoked.corp.example", revoked: true)]);
        var cut = Render(context);

        cut.Find("#show-inactive").Change(true);

        cut.WaitForAssertion(() => Assert.Equal(3, cut.FindAll("tr[data-exception]").Count));
        Assert.Contains(api.Requests, r => r.PathAndQuery == "/v1/pqc-exceptions?includeInactive=true");
    }

    [Theory]
    [InlineData("", "30", "reason")]
    [InlineData("*.corp.example", "30", "reason")]
    [InlineData("10.0.0.1", "30", "reason")]
    [InlineData("legacy.corp.example", "0", "reason")]
    [InlineData("legacy.corp.example", "3651", "reason")]
    [InlineData("legacy.corp.example", "30", "")]
    public async Task CreateForm_ValidatesLocallyBeforeCallingTheApi(string name, string days, string reason)
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var cut = Render(context);

        cut.Find("#pqc-name").Input(name);
        cut.Find("#pqc-days").Input(days);
        cut.Find("#pqc-reason").Input(reason);
        cut.Find("[data-action='create']").Click();

        Assert.NotEmpty(cut.FindAll("[data-test='form-error']"));
        Assert.DoesNotContain(api.Requests, r => r.Method == HttpMethod.Post);
    }

    [Fact]
    public async Task Create_PostsTheExpiryComputedFromTheInjectedClock()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var cut = Render(context);
        FillValid(cut);

        cut.Find("[data-action='create']").Click();

        cut.WaitForAssertion(() =>
        {
            var post = Assert.Single(api.Requests, r => r.Method == HttpMethod.Post && r.PathAndQuery == "/v1/pqc-exceptions");
            using var json = JsonDocument.Parse(post.Body!);
            Assert.Equal("WebServer", json.RootElement.GetProperty("templateTypeKey").GetString());
            Assert.Equal("legacy.corp.example", json.RootElement.GetProperty("namePattern").GetString());
            Assert.Equal("Rsa", json.RootElement.GetProperty("family").GetString());
            Assert.Equal(Now.UtcDateTime.AddDays(30), json.RootElement.GetProperty("expiresAtUtc").GetDateTime().ToUniversalTime());
            Assert.Equal("old load balancer", json.RootElement.GetProperty("reason").GetString());
        });
    }

    [Fact]
    public async Task Revoke_AsksForConfirmation_ThenCallsTheApi()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var active = Exception("legacy.corp.example");
        api.Exceptions.Add(active);
        var cut = Render(context);
        var row = $"tr[data-exception='{active.Id}']";

        cut.Find($"{row} [data-action='revoke']").Click();
        Assert.DoesNotContain(api.Requests, r => r.PathAndQuery.EndsWith("/revoke", StringComparison.Ordinal));

        cut.Find($"{row} [data-action='confirm-revoke']").Click();

        cut.WaitForAssertion(() => Assert.Contains(api.Requests,
            r => r.Method == HttpMethod.Post && r.PathAndQuery == $"/v1/pqc-exceptions/{active.Id}/revoke"));
    }

    [Fact]
    public async Task AServerRefusal_ShowsItsDetail()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.CreateReply = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("""{"title":"Not Found","status":404,"detail":"Template 'WebServer' does not exist."}""",
                Encoding.UTF8, "application/problem+json")
        };
        var cut = Render(context);
        FillValid(cut);

        cut.Find("[data-action='create']").Click();

        cut.WaitForAssertion(() => Assert.Contains("Template 'WebServer' does not exist.", cut.Find("[data-test='notification']").TextContent));
    }

    [Fact]
    public async Task AServerRefusal_ShowsItsCorrelationId()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        var reply = new HttpResponseMessage(HttpStatusCode.InternalServerError)
        {
            Content = new StringContent("""{"title":"Internal Server Error","status":500,"detail":"Boom."}""",
                Encoding.UTF8, "application/problem+json")
        };
        reply.Headers.Add("X-Correlation-Id", "0af7651916cd43dd8448eb211c80319c");
        api.CreateReply = reply;
        var cut = Render(context);
        FillValid(cut);

        cut.Find("[data-action='create']").Click();

        cut.WaitForAssertion(() => Assert.Contains("(correlation id: 0af7651916cd43dd8448eb211c80319c)",
            cut.Find("[data-test='notification']").TextContent));
    }

    [Fact]
    public async Task AServerRefusalWithoutACorrelationId_AddsNothing()
    {
        var (context, api) = NewContext();
        await using var _ = context;
        api.CreateReply = new HttpResponseMessage(HttpStatusCode.NotFound)
        {
            Content = new StringContent("""{"title":"Not Found","status":404,"detail":"Gone."}""",
                Encoding.UTF8, "application/problem+json")
        };
        var cut = Render(context);
        FillValid(cut);

        cut.Find("[data-action='create']").Click();

        cut.WaitForAssertion(() => Assert.Contains("Gone.", cut.Find("[data-test='notification']").TextContent));
        Assert.DoesNotContain("correlation id", cut.Find("[data-test='notification']").TextContent);
    }
}
