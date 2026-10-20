using Qertum.Tests.Web;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Bunit;
using Microsoft.Extensions.Time.Testing;
using Qertum.Services;
using Qertum.Services.Policies;

namespace Qertum.Tests.Enrollment;

/// <summary>
/// Renders the real wizard page against a stub API. Preview requests are held open until a test
/// releases them, and each records the token HttpClient handed the handler, so tests can observe
/// cancellation of the actual HTTP call.
/// </summary>
internal sealed class WizardTestHost : IAsyncDisposable
{
    public WizardTestHost()
    {
        Context.AddAuthorization().SetAuthorized("alice");
        Context.Services.AddAutomationSnippets();
        Context.Services.AddSingleton<TimeProvider>(Time);
        Context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(Api) { BaseAddress = new Uri("http://api.test/") }));
    }

    public BunitContext Context { get; } = new();

    public FakeTimeProvider Time { get; } = new();

    public WizardApiStub Api { get; } = new();

    public ValueTask DisposeAsync() => Context.DisposeAsync();
}

internal sealed class WizardApiStub : HttpMessageHandler
{
    private readonly List<PendingPreview> previews = [];
    private readonly List<CreateCertificateRequestRequest> submitted = [];

    public EnrollmentOptionsResponse Options { get; set; } = DefaultOptions();

    // Initialized by default: every wizard test other than the CA-readiness one assumes a working CA.
    public CaStatusResponse CaStatus { get; set; } = new() { IsInitialized = true };

    public bool FailOptions { get; set; }

    /// <summary>The body the create call answers with; a test sets <c>{"warnings":["…"]}</c> to see them shown.</summary>
    public string SubmitResponseJson { get; set; } = "{}";

    public IReadOnlyList<PendingPreview> Previews
    {
        get { lock (previews) return previews.ToList(); }
    }

    public IReadOnlyList<CreateCertificateRequestRequest> Submitted
    {
        get { lock (submitted) return submitted.ToList(); }
    }

    // Off: the wizard tests exercise classical keys; the CA default is Enforce. WebServer takes
    // webServerStage; the other templates take otherStage, or the same when it is not given.
    public static EnrollmentOptionsResponse DefaultOptions(PqcStage webServerStage = PqcStage.Off, PqcStage? otherStage = null) => new()
    {
        PqcStage = PqcStage.Off,
        Purposes =
        [
            new EnrollmentPurposeOption { Purpose = EnrollmentPurpose.WebServer, TemplateTypeKeys = ["WebServer"] },
            new EnrollmentPurposeOption { Purpose = EnrollmentPurpose.ClientAuthentication, TemplateTypeKeys = ["ClientAuth", "DeviceAuth"] }
        ],
        Templates =
        [
            new EnrollmentTemplateSummary
            {
                TypeKey = "WebServer", Name = "Web Server (TLS)", Description = "TLS server", SanTypes = ["dns", "ip"],
                DefaultValidityDays = 365, Purposes = [EnrollmentPurpose.WebServer], PqcStage = webServerStage
            },
            new EnrollmentTemplateSummary
            {
                TypeKey = "ClientAuth", Name = "Client Authentication", SanTypes = ["email", "upn"],
                DefaultValidityDays = 365, Purposes = [EnrollmentPurpose.ClientAuthentication], PqcStage = otherStage ?? webServerStage
            },
            new EnrollmentTemplateSummary
            {
                TypeKey = "DeviceAuth", Name = "Device Authentication", SanTypes = ["dns"],
                DefaultValidityDays = 90, Purposes = [EnrollmentPurpose.ClientAuthentication], PqcStage = otherStage ?? webServerStage
            }
        ]
    };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var path = request.RequestUri!.AbsolutePath;

        if (request.Method == HttpMethod.Get && path == "/v1/ca/status")
            return Json(CaStatus);

        if (request.Method == HttpMethod.Get && path == "/v1/enrollment/options")
        {
            return FailOptions
                ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
                {
                    Content = new StringContent("{\"title\":\"boom\",\"status\":500}", Encoding.UTF8, "application/problem+json")
                }
                : Json(Options);
        }

        if (request.Method == HttpMethod.Post && path == "/v1/certificate-requests/preview")
        {
            var body = await request.Content!.ReadFromJsonAsync<CreateCertificateRequestRequest>(cancellationToken);
            var pending = new PendingPreview(body!, cancellationToken);
            lock (previews) previews.Add(pending);
            // Deliberately ignores the token: a test may release a superseded call late to prove the
            // page never applies its result.
            return Json(await pending.Response.Task);
        }

        if (request.Method == HttpMethod.Post && path == "/v1/certificate-requests")
        {
            var body = await request.Content!.ReadFromJsonAsync<CreateCertificateRequestRequest>(cancellationToken);
            lock (submitted) submitted.Add(body!);
            return new HttpResponseMessage(HttpStatusCode.Created)
            {
                Content = new StringContent(SubmitResponseJson, Encoding.UTF8, "application/json")
            };
        }

        return new HttpResponseMessage(HttpStatusCode.NotFound);
    }

    private static HttpResponseMessage Json<T>(T value) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value, JsonSerializerOptions.Web), Encoding.UTF8, "application/json")
    };
}

internal sealed class PendingPreview(CreateCertificateRequestRequest request, CancellationToken token)
{
    public CreateCertificateRequestRequest Request { get; } = request;

    public CancellationToken Token { get; } = token;

    public TaskCompletionSource<CertificateRequestPreviewResponse> Response { get; } =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public void Allow() => Response.TrySetResult(new CertificateRequestPreviewResponse
    {
        Allowed = true,
        TemplateTypeKey = Request.Type,
        TemplateExists = true,
        EffectiveValidityDays = 365,
        EffectiveKeyAlgorithm = "ECDSA-P256"
    });

    public void Reject(string message) => Response.TrySetResult(new CertificateRequestPreviewResponse
    {
        Allowed = false,
        TemplateTypeKey = Request.Type,
        TemplateExists = true,
        Violations = [new IssuancePolicyViolation(PolicyRules.DnsSuffix, Request.CommonName, message)]
    });
}
