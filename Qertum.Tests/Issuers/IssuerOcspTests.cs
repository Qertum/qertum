using System.Net.Http.Headers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerOcspTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static readonly Org.BouncyCastle.Asn1.X509.AlgorithmIdentifier Sha1 =
        new(Org.BouncyCastle.Asn1.Oiw.OiwObjectIdentifiers.IdSha1, Org.BouncyCastle.Asn1.DerNull.Instance);

    private static X509Certificate Cert(string pem) => QertumKeyCodec.ReadCertificatePem(pem)!;

    private static ByteArrayContent Request(string serialHex, X509Certificate issuer)
    {
        var generator = new OcspReqGenerator();
        generator.AddRequest(new CertificateID(Sha1, issuer, new BigInteger(serialHex, 16)));
        return new ByteArrayContent(generator.Generate().GetEncoded())
        {
            Headers = { ContentType = new MediaTypeHeaderValue("application/ocsp-request") }
        };
    }

    private static async Task<(BasicOcspResp Basic, object? Status)> AskAsync(HttpClient client, string serial, X509Certificate issuer)
    {
        var response = await client.PostAsync("/ocsp", Request(serial, issuer), Ct);
        var basic = (BasicOcspResp)new OcspResp(await response.Content.ReadAsByteArrayAsync(Ct)).GetResponseObject();
        return (basic, basic.Responses.Single().GetCertStatus());
    }

    private static bool SignedBy(BasicOcspResp basic, X509Certificate issuer) =>
        basic.Verify(QertumKeyCodec.PublicKeyOf(issuer));

    [Fact]
    public async Task EachIssuersSerial_IsAnsweredAndSignedByThatIssuer()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var legacyId = await host.DefaultIssuerIdAsync(Ct);
        var second = await host.Kit.AddOnlineRootAsync("OCSP Second");
        await host.Registry.InvalidateAsync(Ct);
        var legacyCert = Cert(host.Kit.Legacy.GetCaCertificatePem());
        var secondCert = Cert(second.CertificatePem!);
        var legacySerial = await host.SeedIssuedAsync(legacyId, host.Kit.Legacy, revoked: true, Ct);
        var secondSerial = await host.SeedIssuedAsync(second.Id, host.Kit.NewGenerator(host.Kit.Storage.OptionsFor(second)), revoked: true, Ct);
        var client = host.Anonymous();

        var (legacyBasic, legacyStatus) = await AskAsync(client, legacySerial, legacyCert);
        var (secondBasic, secondStatus) = await AskAsync(client, secondSerial, secondCert);

        Assert.IsType<RevokedStatus>(legacyStatus);
        Assert.True(SignedBy(legacyBasic, legacyCert));
        Assert.IsType<RevokedStatus>(secondStatus);
        Assert.True(SignedBy(secondBasic, secondCert));
    }

    [Fact]
    public async Task SerialOfOneIssuer_AskedUnderAnotherIssuersCertId_IsUnknown()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var second = await host.Kit.AddOnlineRootAsync("OCSP Other");
        await host.Registry.InvalidateAsync(Ct);
        var secondSerial = await host.SeedIssuedAsync(second.Id, host.Kit.NewGenerator(host.Kit.Storage.OptionsFor(second)), revoked: true, Ct);

        var (_, status) = await AskAsync(host.Anonymous(), secondSerial, Cert(host.Kit.Legacy.GetCaCertificatePem()));

        Assert.IsType<UnknownStatus>(status);
    }

    [Fact]
    public async Task RetiredIssuer_StillAnswers()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var retired = await host.Kit.AddOnlineRootAsync("OCSP Retired", status: IssuerStatus.Retired);
        await host.Registry.InvalidateAsync(Ct);
        var serial = await host.SeedIssuedAsync(retired.Id, host.Kit.NewGenerator(host.Kit.Storage.OptionsFor(retired)), revoked: true, Ct);

        var (basic, status) = await AskAsync(host.Anonymous(), serial, Cert(retired.CertificatePem!));

        Assert.IsType<RevokedStatus>(status);
        Assert.True(SignedBy(basic, Cert(retired.CertificatePem!)));
    }

    [Fact]
    public async Task ForeignIssuer_IsUnknown_SignedByTheDefault()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var foreign = host.Kit.NewGenerator(new CaDataOptions { Directory = Path.Combine(host.Kit.CaDataDirectory, "foreign") });
        foreign.GenerateCa(new GenerateCaRequest { CommonName = "Foreign", ValidityDays = 30 });

        var (basic, status) = await AskAsync(host.Anonymous(), "0A1B2C", Cert(foreign.GetCaCertificatePem()));

        Assert.IsType<UnknownStatus>(status);
        Assert.True(SignedBy(basic, Cert(host.Kit.Legacy.GetCaCertificatePem())));
    }
}
