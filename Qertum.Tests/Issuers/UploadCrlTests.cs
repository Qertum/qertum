using System.Net;
using System.Net.Http.Json;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class UploadCrlTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<(IssuerApiHost Host, (AsymmetricCipherKeyPair Key, X509Certificate Cert) Root, IssuerId RootId, IssuerId IntermediateId, X509Certificate Intermediate)> SetUpAsync()
    {
        var host = new IssuerApiHost();
        var root = CaCertificateBuilderTests.Root();
        var pending = await IssuerCeremonyTestSteps.PendingAsync(host);
        var cert = IssuerCeremonyTestSteps.Sign(root, pending.RequestFile!);
        (await IssuerCeremonyTestSteps.InstallAsync(host, pending.Issuer.Id, cert, root.Cert)).EnsureSuccessStatusCode();
        var rootId = (await host.Admin().GetFromJsonAsync<List<IssuerResponse>>("/v1/issuers", Ct))!.Single(i => i.Kind == IssuerKind.Root).Id;
        return (host, root, rootId, pending.Issuer.Id, cert);
    }

    private static byte[] Crl((AsymmetricCipherKeyPair Key, X509Certificate Cert) root, long number, DateTime nextUpdate, params string[] revokedSerials) =>
        CaCertificateBuilder.BuildCrl(new LocalKeyPairCaSigner(root.Key), root.Cert,
            revokedSerials.Select(s => new OfflineRevocation(s, DateTime.UtcNow.AddMinutes(-1), "cessationOfOperation")),
            number, DateTime.UtcNow.AddMinutes(-1), nextUpdate);

    private static Task<HttpResponseMessage> UploadAsync(IssuerApiHost host, IssuerId id, byte[] der) =>
        host.Admin().PostAsync($"/v1/issuers/{id}/crl", new ByteArrayContent(der)
        {
            Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/pkix-crl") }
        }, Ct);

    [Fact]
    public async Task ValidCrl_IsStoredAndServedAsIs()
    {
        var (host, root, rootId, _, _) = await SetUpAsync();
        await using var _h = host;
        var der = Crl(root, 1, DateTime.UtcNow.AddDays(365));

        Assert.Equal(HttpStatusCode.OK, (await UploadAsync(host, rootId, der)).StatusCode);
        Assert.Equal(der, await host.Anonymous().GetByteArrayAsync($"/crl/{rootId}", Ct));
    }

    [Fact]
    public async Task PemBody_IsAccepted()
    {
        var (host, root, rootId, _, _) = await SetUpAsync();
        await using var _h = host;
        var der = Crl(root, 1, DateTime.UtcNow.AddDays(30));
        var pem = "-----BEGIN X509 CRL-----\n" + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks) + "\n-----END X509 CRL-----\n";

        var response = await host.Admin().PostAsync($"/v1/issuers/{rootId}/crl", new StringContent(pem), Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ForeignSignature_Stale_AndExpired_Are400()
    {
        var (host, root, rootId, _, _) = await SetUpAsync();
        await using var _h = host;
        var foreign = CaCertificateBuilderTests.Root(cn: root.Cert.SubjectDN.GetValueList(Org.BouncyCastle.Asn1.X509.X509Name.CN)[0]);
        (await UploadAsync(host, rootId, Crl(root, 5, DateTime.UtcNow.AddDays(30)))).EnsureSuccessStatusCode();

        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(host, rootId, Crl(foreign, 6, DateTime.UtcNow.AddDays(30)))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(host, rootId, Crl(root, 5, DateTime.UtcNow.AddDays(30)))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await UploadAsync(host, rootId, Crl(root, 7, DateTime.UtcNow.AddMinutes(-1)))).StatusCode);
    }

    [Fact]
    public async Task OnlineIssuer_Is409()
    {
        var (host, _, _, intermediateId, _) = await SetUpAsync();
        await using var _h = host;

        Assert.Equal(HttpStatusCode.Conflict, (await UploadAsync(host, intermediateId, [0x30, 0x00])).StatusCode);
    }

    [Fact]
    public async Task RevokedIntermediate_IsRetiredAndLosesDefault()
    {
        var (host, root, rootId, intermediateId, intermediate) = await SetUpAsync();
        await using var _h = host;

        (await UploadAsync(host, rootId, Crl(root, 1, DateTime.UtcNow.AddDays(30), intermediate.SerialNumber.ToString(16)))).EnsureSuccessStatusCode();

        var after = await host.Admin().GetFromJsonAsync<IssuerResponse>($"/v1/issuers/{intermediateId}", Ct);
        Assert.Equal(IssuerStatus.Retired, after!.Status);
        Assert.False(after.IsDefault);
    }
}
