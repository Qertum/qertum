using System.Net;
using System.Net.Http.Json;
using Qertum.Services;

namespace Qertum.Tests.Issuers;

/// <summary>The API's "the CA" endpoints answer for the default issuer.</summary>
public sealed class DefaultIssuerApiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task CaStatus_NamesTheDefaultIssuer()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Status Root");

        var status = await host.Admin().GetFromJsonAsync<CaStatusResponse>("/v1/ca/status", Ct);

        Assert.True(status!.IsInitialized);
        Assert.Equal("Status Root", status.DefaultIssuerName);
        Assert.NotNull(status.DefaultIssuerId);
    }

    [Fact]
    public async Task Generate_WhileADefaultIssuerExists_Is409()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Exists");

        var response = await host.Admin().PostAsJsonAsync("/v1/ca/generate", new GenerateCaRequest { CommonName = "Second" }, Ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task CaCertificate_IsTheDefaultIssuersRoot()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Root Download");

        var pem = await host.Admin().GetStringAsync("/v1/ca/certificate", Ct);

        Assert.Equal(host.Kit.Legacy.GetCaCertificatePem().Trim(), pem.Trim());
    }

    [Fact]
    public async Task RequestDetail_CarriesTheIssuerName()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy("Named Root");
        var issuerId = await host.DefaultIssuerIdAsync(Ct);
        var row = new CertificateRequest { CommonName = "n.example", RequestedBy = "t", Status = CertificateRequestStatus.Issued, IssuerId = issuerId };
        await using (var db = host.Kit.Database.CreateContext())
        {
            db.CertificateRequests.Add(row);
            await db.SaveChangesAsync(Ct);
        }

        var detail = await host.Admin().GetFromJsonAsync<CertificateRequest>($"/v1/certificate-requests/{row.Id}", Ct);

        Assert.Equal("Named Root", detail!.IssuerName);
    }
}
