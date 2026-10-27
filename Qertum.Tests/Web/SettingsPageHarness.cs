using System.Net;
using System.Text;
using Bunit;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.JSInterop;
using Qertum.Services;

namespace Qertum.Tests.Web;

/// <summary>A Settings page rendered for a <c>settings.edit</c> holder against a stubbed API.</summary>
internal static class SettingsPageHarness
{
    /// <summary>Every request the page made, in order. Registered in the context's services.</summary>
    internal sealed class RequestLog
    {
        public List<(HttpMethod Method, string Path, string? Body)> Requests { get; } = [];
    }

    public static BunitContext NewContext(
        string caStatusJson = """{"isInitialized":true,"algorithm":"RSA"}""", bool admin = false, string pqcStage = "Off",
        bool requireIndependentCaApproval = true, bool recoveryStatusFails = false, bool requireTwoPersonApproval = false,
        string issuerStrength = "Warn", string revokedIssuer = "HardStop")
    {
        var context = new BunitContext();
        context.Services.AddSingleton(TimeProvider.System);
        var auth = context.AddAuthorization().SetAuthorized("alice").SetPolicies(AppPermissions.SettingsEdit);
        if (admin)
            auth.SetRoles("admin");
        context.JSInterop.Mode = JSRuntimeMode.Loose;
        var log = new RequestLog();
        context.Services.AddSingleton(log);
        context.Services.AddSingleton(new CertificateRequestsApiClient(
            new HttpClient(new SettingsStub(caStatusJson, pqcStage, requireIndependentCaApproval, recoveryStatusFails, requireTwoPersonApproval, issuerStrength, revokedIssuer, log)) { BaseAddress = new Uri("http://api.test/") }));
        return context;
    }

    private sealed class SettingsStub(string caStatusJson, string pqcStage, bool requireIndependentCaApproval, bool recoveryStatusFails, bool requireTwoPersonApproval, string issuerStrength, string revokedIssuer, RequestLog log) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? null : await request.Content.ReadAsStringAsync(cancellationToken);
            lock (log) log.Requests.Add((request.Method, request.RequestUri!.AbsolutePath, body));
            if (recoveryStatusFails && request.RequestUri!.AbsolutePath == "/v1/recovery-status")
                return new HttpResponseMessage(HttpStatusCode.InternalServerError);
            var json = request.RequestUri!.AbsolutePath switch
            {
                "/v1/settings/pqc-stage" => $$"""{"id":1,"organizationName":"Test Org","pqcStage":{{System.Text.Json.JsonSerializer.Serialize(
                    System.Text.Json.JsonDocument.Parse(body ?? "{}").RootElement.GetProperty("stage").GetString())}}}""",
                "/v1/settings/issuer-strength" => $$"""{"id":1,"organizationName":"Test Org","pqcStage":"{{pqcStage}}","requireIndependentCaApproval":true,"issuerStrengthMode":{{System.Text.Json.JsonSerializer.Serialize(
                    System.Text.Json.JsonDocument.Parse(body ?? "{}").RootElement.GetProperty("mode").GetString())}}}""",
                "/v1/settings/revoked-issuer" => $$"""{"id":1,"organizationName":"Test Org","pqcStage":"{{pqcStage}}","requireIndependentCaApproval":true,"revokedIssuerMode":{{System.Text.Json.JsonSerializer.Serialize(
                    System.Text.Json.JsonDocument.Parse(body ?? "{}").RootElement.GetProperty("mode").GetString())}}}""",
                "/v1/settings/ca-approval" => $$"""{"id":1,"organizationName":"Test Org","pqcStage":"{{pqcStage}}","requireIndependentCaApproval":{{(System.Text.Json.JsonDocument.Parse(body ?? "{}").RootElement.GetProperty("requireIndependentApproval").GetBoolean() ? "true" : "false")}}}""",
                "/v1/settings/two-person-approval" => $$"""{"id":1,"organizationName":"Test Org","pqcStage":"{{pqcStage}}","requireIndependentCaApproval":true,"requireTwoPersonApproval":{{(System.Text.Json.JsonDocument.Parse(body ?? "{}").RootElement.GetProperty("enabled").GetBoolean() ? "true" : "false")}}}""",
                "/v1/settings" => $$"""{"id":1,"organizationName":"Test Org","pqcStage":"{{pqcStage}}","requireIndependentCaApproval":{{(requireIndependentCaApproval ? "true" : "false")}},"requireTwoPersonApproval":{{(requireTwoPersonApproval ? "true" : "false")}},"issuerStrengthMode":"{{issuerStrength}}","revokedIssuerMode":"{{revokedIssuer}}"}""",
                "/v1/ca/status" => caStatusJson,
                "/v1/recovery-status" => """{"generatedAtUtc":"2026-10-06T12:00:00Z","backup":{"state":"NotReported"},"restore":{"state":"NotReported"}}""",
                "/v1/secret-storage/status" => """{"currentProvider":"Local","tpmAvailable":false}""",
                "/v1/webhook-destinations" => """{"publicMode":"AnyPublic","initialized":true,"rules":[]}""",
                _ => "[]"
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            };
        }
    }
}
