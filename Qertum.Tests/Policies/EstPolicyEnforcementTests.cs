using System.Net;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;

namespace Qertum.Tests.Policies;

/// <summary>
/// Uses its own factory per test: <c>EstProtocolTests</c> shares one fixture across its class, and a
/// policy linked to WebServer there would change the outcome of every other test in it.
/// </summary>
public sealed class EstPolicyEnforcementTests
{
    private static async Task LinkWebServerPolicyAsync(EstTestFactory factory, CancellationToken ct)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
        await PolicySeeding.LinkPublishedPolicyAsync(db, "WebServer", dnsSuffixes: ["corp.example.com"], ct: ct);
    }

    private static Task<HttpResponseMessage> EnrollAsync(HttpClient client, string commonName, CancellationToken ct) =>
        client.PostAsync("/.well-known/est/simpleenroll",
            new StringContent(TestCsrBuilder.BuildBase64Url(subjectCn: commonName, sanDnsNames: []),
                System.Text.Encoding.ASCII, "application/pkcs10"), ct);

    [Fact]
    public async Task Simpleenroll_NameOutsideTheIssuersNameConstraints_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = new EstTestFactory();
        using var client = factory.CreateAuthenticatedClient();
        using (var scope = factory.Services.CreateScope())
        {
            // A registered default issuer that permits only corp.example.com; LegacyFiles makes the
            // registry sign with the host's stub generator. Only the constraint columns matter here.
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            db.Issuers.Add(new Issuer
            {
                Name = "Constrained", Kind = IssuerKind.Root, KeyCustody = IssuerKeyCustody.Online,
                Status = IssuerStatus.Active, IsDefault = true, LegacyFiles = true,
                CertificatePem = "stub", SpkiSha256 = "00", PermittedDnsSuffixesJson = "[\"corp.example.com\"]",
                CreatedAtUtc = DateTime.UtcNow
            });
            await db.SaveChangesAsync(ct);
        }

        var response = await EnrollAsync(client, "device.other.example", ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("device.other.example", await response.Content.ReadAsStringAsync(ct));
        using var verify = factory.Services.CreateScope();
        Assert.False(await verify.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AnyAsync(r => r.CommonName == "device.other.example", ct));
    }

    [Fact]
    public async Task Simpleenroll_NameOutsideIssuancePolicy_Returns400AndCreatesNoRequest()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = new EstTestFactory();
        using var client = factory.CreateAuthenticatedClient();
        await LinkWebServerPolicyAsync(factory, ct);

        var response = await EnrollAsync(client, "device.other.example", ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("device.other.example", await response.Content.ReadAsStringAsync(ct));
        using var verify = factory.Services.CreateScope();
        Assert.False(await verify.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AnyAsync(r => r.CommonName == "device.other.example", ct));
    }

    [Fact]
    public async Task Simpleenroll_FollowsTheConfiguredEstTemplateKey()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = new EstTestFactory();
        using var client = factory.CreateAuthenticatedClient();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<CertificateRequestDbContext>();
            var settings = await db.Settings.SingleOrDefaultAsync(s => s.Id == 1, ct);
            if (settings is null)
            {
                settings = new CaSettings { PqcStage = PqcStage.Off };
                db.Settings.Add(settings);
            }
            settings.EstTemplateTypeKey = "ClientAuth";
            await db.SaveChangesAsync(ct);
            // The policy is on ClientAuth, not WebServer: it only bites if the key is honoured.
            await PolicySeeding.LinkPublishedPolicyAsync(db, "ClientAuth", dnsSuffixes: ["corp.example.com"], ct: ct);
        }

        var refused = await EnrollAsync(client, "device.other.example", ct);
        var accepted = await EnrollAsync(client, "device.corp.example.com", ct);

        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(HttpStatusCode.Accepted, accepted.StatusCode);
        using var verify = factory.Services.CreateScope();
        var row = await verify.ServiceProvider.GetRequiredService<CertificateRequestDbContext>()
            .CertificateRequests.AsNoTracking().SingleAsync(r => r.CommonName == "device.corp.example.com", ct);
        Assert.Equal("ClientAuth", row.Type);
    }

    [Fact]
    public async Task Simpleenroll_NameInsideIssuancePolicy_IsAccepted()
    {
        var ct = TestContext.Current.CancellationToken;
        using var factory = new EstTestFactory();
        using var client = factory.CreateAuthenticatedClient();
        await LinkWebServerPolicyAsync(factory, ct);

        var response = await EnrollAsync(client, "device.corp.example.com", ct);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }
}
