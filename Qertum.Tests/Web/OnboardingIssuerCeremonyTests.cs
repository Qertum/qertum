using System.Text.Json;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Web.Components.Pages;

namespace Qertum.Tests.Web;

public sealed class OnboardingIssuerCeremonyTests
{
    private static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web);

    private static HttpResponseMessage Json(object value) => new(System.Net.HttpStatusCode.OK)
    {
        Content = new StringContent(JsonSerializer.Serialize(value, Web), System.Text.Encoding.UTF8, "application/json")
    };

    private static BunitContext NewContext(CaStatusResponse status, bool admin = true)
    {
        var api = new IssuerApiStub();
        api.Override = r =>
        {
            var path = r.RequestUri!.AbsolutePath;
            if (path == "/v1/ca/status") return Json(status);
            if (status.PendingIntermediateIssuerId is { } pending && path == $"/v1/issuers/{pending}/request")
                return Json(new IntermediateRequestFile(IntermediateRequestFile.CurrentFormat, pending, "Waiting",
                    "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n", 1825, 0, [], [], [], []));
            return null;
        };
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        var auth = context.AddAuthorization().SetAuthorized("admin").SetPolicies(AppPermissions.SettingsEdit);
        if (admin) auth.SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        context.Services.AddSingleton(new CertificateRequestsApiClient(new HttpClient(api) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    [Fact]
    public async Task OfflineRootCard_IsOfferedAndMarkedRecommended()
    {
        await using var context = NewContext(new CaStatusResponse { IsInitialized = false });

        var cut = context.Render<Onboarding>();

        var card = cut.FindAll("button.option-card").Single(b => b.TextContent.Contains("Offline root", StringComparison.Ordinal));
        Assert.Contains("Recommended", card.TextContent);
        card.Click();
        Assert.NotEmpty(cut.FindAll("#ceremony-name"));
    }

    [Fact]
    public async Task OfflineRootCard_IsHiddenFromNonAdmins()
    {
        await using var context = NewContext(new CaStatusResponse { IsInitialized = false }, admin: false);

        var cut = context.Render<Onboarding>();

        Assert.DoesNotContain(cut.FindAll("button.option-card"), b => b.TextContent.Contains("Offline root", StringComparison.Ordinal));
    }

    [Fact]
    public async Task PendingIntermediate_ResumesAtTheInstallStep()
    {
        await using var context = NewContext(new CaStatusResponse { IsInitialized = false, PendingIntermediateIssuerId = new IssuerId(Guid.NewGuid()) });

        var cut = context.Render<Onboarding>();

        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='cert-file']")));
    }

    private const string PendingCsr = "-----BEGIN CERTIFICATE REQUEST-----\nAA==\n-----END CERTIFICATE REQUEST-----\n";

    [Fact]
    public async Task SignStep_DownloadCsr_SavesOnlyTheCsrPem()
    {
        var pending = new IssuerId(Guid.NewGuid());
        await using var context = NewContext(new CaStatusResponse { IsInitialized = false, PendingIntermediateIssuerId = pending });
        var cut = context.Render<Onboarding>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='ceremony-download-csr']")));

        cut.Find("[data-test='ceremony-download-csr']").Click();

        var call = Assert.Single(context.JSInterop.Invocations, i => i.Identifier == "downloadFile");
        Assert.Equal($"{pending}.csr.pem", call.Arguments[0]);
        var saved = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String((string)call.Arguments[2]!));
        Assert.Equal(PendingCsr, saved);
        Assert.DoesNotContain("qertum-intermediate-request", saved, StringComparison.Ordinal);
    }

    [Fact]
    public async Task SignStep_DownloadFullRequestFile_StillSavesTheJson()
    {
        var pending = new IssuerId(Guid.NewGuid());
        await using var context = NewContext(new CaStatusResponse { IsInitialized = false, PendingIntermediateIssuerId = pending });
        var cut = context.Render<Onboarding>();
        cut.WaitForAssertion(() => Assert.NotEmpty(cut.FindAll("[data-test='ceremony-download-request']")));

        cut.Find("[data-test='ceremony-download-request']").Click();

        var call = Assert.Single(context.JSInterop.Invocations, i => i.Identifier == "downloadFile");
        Assert.Equal($"{pending}.request.json", call.Arguments[0]);
        using var doc = JsonDocument.Parse(Convert.FromBase64String((string)call.Arguments[2]!));
        Assert.Equal(IntermediateRequestFile.CurrentFormat, doc.RootElement.GetProperty("format").GetString());
        Assert.Equal(PendingCsr, doc.RootElement.GetProperty("csrPem").GetString());
    }
}
