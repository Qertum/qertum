using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Issuers;
using Qertum.Services.Policies;

namespace Qertum.Tests.Issuers;

/// <summary>
/// Approval checks the CA permission and the independent-approver rule only when the request's template is CA-capable at
/// that moment, while the queue consumer signs with the template as it is when it signs. Someone who may edit templates
/// could add KeyCertSign to the template of an approved leaf request in between and have a subordinate CA issued that
/// nobody with certificates.ca approved (CWE-367, GitHub AI Scan on the 1.0.0-rc5 snapshot). The consumer now signs from
/// a CA-capable template only a request a person approved as a CA certificate.
/// </summary>
public sealed class CaApprovalBindingTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly string[] LeafOperator =
        [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate, AppPermissions.CertificatesManage];

    private static readonly string[] CaOperator =
        [AppPermissions.CertificatesView, AppPermissions.CertificatesCreate, AppPermissions.CertificatesManage, AppPermissions.CertificatesCa];

    private static async Task<IssuerApiHost> HostAsync()
    {
        var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Root");
        await host.GrantAsync("leaf-op", LeafOperator);
        await host.GrantAsync("ca-op", CaOperator);
        return host;
    }

    private static async Task<CertificateRequestId> CreateAndApproveAsync(IssuerApiHost host, string type, string role)
    {
        var created = await host.Sub("alice", role).PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = "app.example.com", Type = type, PropertiesJson = "{}" }, Ct);
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var id = (await created.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!.Id;
        var approved = await host.Sub("bob", role).PostAsync($"/v1/certificate-requests/{(Guid)id}/approve", null, Ct);
        Assert.True(approved.IsSuccessStatusCode, await approved.Content.ReadAsStringAsync(Ct));
        return id;
    }

    /// <summary>What the consumer's dequeue does: the approved row becomes Processing before it is checked and signed.</summary>
    private static async Task<CertificateRequest> ClaimAsync(IssuerApiHost host, CertificateRequestId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        var row = await db.CertificateRequests.SingleAsync(r => r.Id == id, Ct);
        row.Status = CertificateRequestStatus.Processing;
        await db.SaveChangesAsync(Ct);
        return row;
    }

    private static async Task MakeCaCapableAsync(IssuerApiHost host, string typeKey)
    {
        await using var db = host.Kit.Database.CreateContext();
        var template = await db.CertificateTemplates.SingleAsync(t => t.TypeKey == typeKey, Ct);
        template.KeyUsagesJson = """["DigitalSignature","KeyCertSign","CrlSign"]""";
        await db.SaveChangesAsync(Ct);
    }

    private static async Task<bool> ApprovedAsCaAsync(IssuerApiHost host, CertificateRequestId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        return (await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == id, Ct)).ApprovedAsCaCertificate;
    }

    [Fact]
    public async Task ALeafTemplateMadeCaCapableAfterApproval_IsRejectedBeforeSigning_AndTheSignerRefusesIt()
    {
        await using var host = await HostAsync();
        var id = await CreateAndApproveAsync(host, "WebServer", "leaf-op");
        Assert.False(await ApprovedAsCaAsync(host, id));

        await MakeCaCapableAsync(host, "WebServer"); // someone with settings.edit, after approval
        var row = await ClaimAsync(host, id);

        using var scope = host.Factory.Services.CreateScope();
        // The signer checks the template it signs with, whatever the earlier check saw.
        var refused = await Assert.ThrowsAsync<IssuancePolicyViolationException>(() =>
            scope.ServiceProvider.GetRequiredService<IssuanceSigner>().SignAsync(row, new CaSettings { PqcStage = PqcStage.Off }, Ct));
        Assert.Contains(refused.Decision.Violations, v => v.Rule == PolicyRules.CaPermission);

        var decision = await scope.ServiceProvider.GetRequiredService<ICertificateRequestService>().CheckIssuancePolicyAsync(id, Ct);
        Assert.False(decision.Allowed);
        Assert.Contains(decision.Violations, v => v.Rule == PolicyRules.CaPermission && v.Value == "WebServer");
        await using var db = host.Kit.Database.CreateContext();
        var after = await db.CertificateRequests.AsNoTracking().SingleAsync(r => r.Id == id, Ct);
        Assert.Equal(CertificateRequestStatus.Rejected, after.Status);
        Assert.Null(after.CertificatePem);
    }

    [Fact]
    public async Task ACaRequestApprovedByAnotherCaOperator_IsBoundAndStillSigns()
    {
        await using var host = await HostAsync();
        var id = await CreateAndApproveAsync(host, "SubordinateCA", "ca-op");
        Assert.True(await ApprovedAsCaAsync(host, id));

        var row = await ClaimAsync(host, id);
        using var scope = host.Factory.Services.CreateScope();
        Assert.True((await scope.ServiceProvider.GetRequiredService<ICertificateRequestService>().CheckIssuancePolicyAsync(id, Ct)).Allowed);
        var signed = await scope.ServiceProvider.GetRequiredService<IssuanceSigner>().SignAsync(row, new CaSettings { PqcStage = PqcStage.Off }, Ct);
        Assert.False(string.IsNullOrEmpty(signed.CertificatePem));
    }

    [Fact]
    public async Task AnAutomaticApproval_NeverAuthorizesACaCertificate()
    {
        await using var host = await HostAsync();
        var created = await host.Sub("alice", "ca-op").PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = "sub.example.com", Type = "SubordinateCA", PropertiesJson = "{}" }, Ct);
        var id = (await created.Content.ReadFromJsonAsync<CertificateRequest>(Ct))!.Id;

        using var scope = host.Factory.Services.CreateScope();
        var requests = scope.ServiceProvider.GetRequiredService<ICertificateRequestService>();
        Assert.NotNull(await requests.MarkAsAutoApprovedAsync(id, "auto-renewal", "AutoRenewalAutoApprove", Ct));
        Assert.False(await ApprovedAsCaAsync(host, id));

        await ClaimAsync(host, id);
        Assert.False((await requests.CheckIssuancePolicyAsync(id, Ct)).Allowed);
    }

    [Fact]
    public async Task ALeafRequestOnALeafTemplate_IsUnaffected()
    {
        await using var host = await HostAsync();
        var id = await CreateAndApproveAsync(host, "WebServer", "leaf-op");
        var row = await ClaimAsync(host, id);

        using var scope = host.Factory.Services.CreateScope();
        Assert.True((await scope.ServiceProvider.GetRequiredService<ICertificateRequestService>().CheckIssuancePolicyAsync(id, Ct)).Allowed);
        var signed = await scope.ServiceProvider.GetRequiredService<IssuanceSigner>().SignAsync(row, new CaSettings { PqcStage = PqcStage.Off }, Ct);
        Assert.False(string.IsNullOrEmpty(signed.CertificatePem));
    }
}
