using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerConstraintEnforcementTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    /// <summary>A pathLen-0 intermediate permitting only corp.example, signed by the legacy root; optionally made default.</summary>
    private static async Task<IssuerId> ConstrainedIntermediateAsync(IssuerApiHost host, bool makeDefault)
    {
        var legacy = await host.DefaultIssuerIdAsync(Ct);
        var created = await (await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", new CreateIntermediateRequest
        {
            Name = "Corp Issuing", CommonName = "Corp Issuing", KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256,
            ValidityDays = 365, PathLength = 0, PermittedDnsSuffixes = ["corp.example"], ParentIssuerId = legacy
        }, Ct)).Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct);
        if (makeDefault)
        {
            await using var db = host.Kit.Database.CreateContext();
            await db.Issuers.Where(i => i.Id == legacy).ExecuteUpdateAsync(x => x.SetProperty(i => i.IsDefault, false), Ct);
            await db.Issuers.Where(i => i.Id == created!.Issuer.Id).ExecuteUpdateAsync(x => x.SetProperty(i => i.IsDefault, true), Ct);
            await host.Registry.InvalidateAsync(Ct);
        }
        return created!.Issuer.Id;
    }

    private static Task<HttpResponseMessage> CreateAsync(IssuerApiHost host, string commonName, string type = "WebServer") =>
        host.Admin().PostAsJsonAsync("/v1/certificate-requests",
            new CreateCertificateRequestRequest { CommonName = commonName, Type = type, PropertiesJson = "{}" }, Ct);

    [Fact]
    public async Task Create_OutsideTheIssuersNames_Is400WithTheRule()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await ConstrainedIntermediateAsync(host, makeDefault: true);

        var response = await CreateAsync(host, "www.evil.example");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync(Ct);
        Assert.Contains("issuerNameConstraints", body);
        Assert.Contains("www.evil.example", body);
        Assert.Equal(HttpStatusCode.Created, (await CreateAsync(host, "www.corp.example")).StatusCode);
    }

    [Fact]
    public async Task Preview_OutsideTheIssuersNames_IsAllowedFalse()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await ConstrainedIntermediateAsync(host, makeDefault: true);

        var response = await host.Admin().PostAsJsonAsync("/v1/certificate-requests/preview",
            new CreateCertificateRequestRequest { CommonName = "www.evil.example", Type = "WebServer", PropertiesJson = "{}" }, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var preview = await response.Content.ReadFromJsonAsync<CertificateRequestPreviewResponse>(Ct);
        Assert.False(preview!.Allowed);
        Assert.Contains(preview.Violations, v => v.Rule == Qertum.Services.Policies.PolicyRules.IssuerNameConstraints);
    }

    [Fact]
    public async Task Approve_AfterTheDefaultBecameConstrained_Is422_AndStaysPending()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var created = await (await CreateAsync(host, "www.evil.example")).Content.ReadFromJsonAsync<CertificateRequest>(Ct);
        await ConstrainedIntermediateAsync(host, makeDefault: true);

        var approve = await host.Admin().PostAsync($"/v1/certificate-requests/{created!.Id}/approve", null, Ct);

        Assert.Equal(HttpStatusCode.UnprocessableEntity, approve.StatusCode);
        var after = await host.Admin().GetFromJsonAsync<CertificateRequest>($"/v1/certificate-requests/{created.Id}", Ct);
        Assert.Equal(CertificateRequestStatus.Pending, after!.Status);
    }

    [Fact]
    public async Task ConsumerCheck_RejectsOutsideNames()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await ConstrainedIntermediateAsync(host, makeDefault: true);
        var row = new CertificateRequest { CommonName = "www.evil.example", RequestedBy = "seed", Type = "WebServer", Status = CertificateRequestStatus.Processing };
        await using (var db = host.Kit.Database.CreateContext()) { db.CertificateRequests.Add(row); await db.SaveChangesAsync(Ct); }

        using var scope = host.Factory.Services.CreateScope();
        var decision = await scope.ServiceProvider.GetRequiredService<ICertificateRequestService>().CheckIssuancePolicyAsync(row.Id, Ct);

        Assert.False(decision.Allowed);
        Assert.Contains(decision.Violations, v => v.Rule == Qertum.Services.Policies.PolicyRules.IssuerNameConstraints);
    }

    [Fact]
    public async Task SubordinateCaTemplate_UnderPathLengthZero_Is400()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await ConstrainedIntermediateAsync(host, makeDefault: true);

        var response = await CreateAsync(host, "Sub CA", type: "SubordinateCA");

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("issuerPathLength", await response.Content.ReadAsStringAsync(Ct));
    }
}
