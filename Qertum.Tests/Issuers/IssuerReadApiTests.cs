using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerReadApiTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task List_RequiresCertificatesView()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();

        Assert.Equal(HttpStatusCode.Unauthorized, (await host.Anonymous().GetAsync("/v1/issuers", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.Role("nobody").GetAsync("/v1/issuers", Ct)).StatusCode);
        await host.GrantAsync("reader", AppPermissions.CertificatesView);
        var list = await host.Role("reader").GetFromJsonAsync<List<IssuerResponse>>("/v1/issuers", Ct);
        Assert.True(Assert.Single(list!).IsDefault);
    }

    [Fact]
    public async Task Response_HasNoKeyOrCsrMaterial()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();

        var json = await host.Admin().GetStringAsync("/v1/issuers", Ct);

        Assert.DoesNotContain("PRIVATE KEY", json);
        Assert.DoesNotContain("CERTIFICATE REQUEST", json);
        using var doc = JsonDocument.Parse(json);
        var names = doc.RootElement[0].EnumerateObject().Select(p => p.Name).ToList();
        Assert.DoesNotContain(names, n => n.Contains("key", StringComparison.OrdinalIgnoreCase)
                                          && n is not ("keyAlgorithm" or "keyCustody"));
    }

    [Fact]
    public async Task Certificate_IsPublic_InPemAndDer()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var id = await host.DefaultIssuerIdAsync(Ct);
        var client = host.Anonymous();

        var pem = await client.GetStringAsync($"/v1/issuers/{id}/certificate", Ct);
        var der = await client.GetByteArrayAsync($"/v1/issuers/{id}/certificate?format=der", Ct);

        Assert.Equal(host.Kit.Legacy.GetCaCertificatePem().Trim(), pem.Trim());
        Assert.Equal(X509Certificate2.CreateFromPem(pem).RawData, X509CertificateLoader.LoadCertificate(der).RawData);
    }

    [Fact]
    public async Task Chain_OfAnIntermediate_EndsWithTheRoot()
    {
        await using var host = new IssuerApiHost();
        var root = await host.Kit.AddOnlineRootAsync("Chain Root", isDefault: true);
        var other = await host.Kit.AddOnlineRootAsync("Stand-in Intermediate");
        await using (var db = host.Kit.Database.CreateContext())
        {
            var row = await db.Issuers.FindAsync([other.Id], Ct);
            row!.Kind = IssuerKind.Intermediate;
            row.ParentIssuerId = root.Id;
            await db.SaveChangesAsync(Ct);
        }
        await host.Registry.InvalidateAsync(Ct);

        var pem = await host.Anonymous().GetStringAsync($"/v1/issuers/{other.Id}/chain", Ct);
        var p7b = await host.Anonymous().GetByteArrayAsync($"/v1/issuers/{other.Id}/chain?format=p7b", Ct);

        Assert.EndsWith(root.CertificatePem!.Trim(), pem.Trim());
        var cms = new System.Security.Cryptography.Pkcs.SignedCms();
        cms.Decode(p7b);
        Assert.Equal(2, cms.Certificates.Count);
    }

    [Fact]
    public async Task TrustBundle_HoldsEachActiveOrRetiredRootOnce()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        await host.Kit.AddOnlineRootAsync("Retired Root", status: IssuerStatus.Retired);
        await host.Kit.AddOnlineRootAsync("Archived Root", status: IssuerStatus.Archived);
        await host.Registry.InvalidateAsync(Ct);

        var bundle = await host.Anonymous().GetStringAsync("/v1/issuers/trust-bundle", Ct);

        Assert.Equal(2, bundle.Split("BEGIN CERTIFICATE").Length - 1);
    }

    [Theory]
    [InlineData("certificate")]
    [InlineData("chain")]
    public async Task UnknownIssuer_Is404(string route)
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();

        var response = await host.Anonymous().GetAsync($"/v1/issuers/{Guid.NewGuid()}/{route}", Ct);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Chain_OfACompositeRoot_ExportsDerAndP7b()
    {
        await using var host = new IssuerApiHost();
        var composite = Enum.GetValues<CertificateKeyAlgorithm>().First(a => a.GetFamily() == AlgorithmFamily.Composite);
        var root = await host.Kit.AddOnlineRootAsync("Composite Root", isDefault: true, algorithm: composite);
        await host.Registry.InvalidateAsync(Ct);

        var der = await host.Anonymous().GetByteArrayAsync($"/v1/issuers/{root.Id}/certificate?format=der", Ct);
        var p7b = await host.Anonymous().GetByteArrayAsync($"/v1/issuers/{root.Id}/chain?format=p7b", Ct);

        Assert.Equal(Qertum.Services.Crypto.QertumKeyCodec.ReadCertificatePem(root.CertificatePem!)!.GetEncoded(), der);
        var cms = new System.Security.Cryptography.Pkcs.SignedCms();
        cms.Decode(p7b);
        Assert.Single(cms.Certificates);
    }
}
