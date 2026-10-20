using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Qertum.QueueConsumer;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerCrlTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    [Fact]
    public async Task LegacyScope_IncludesRowsWithNullIssuerId()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var serial = await host.SeedIssuedAsync(issuerId: null, host.Kit.Legacy, revoked: true, Ct);

        var crl = new X509CrlParser().ReadCrl(await host.Anonymous().GetByteArrayAsync("/crl", Ct));

        Assert.NotNull(crl.GetRevokedCertificate(new BigInteger(serial, 16)));
    }

    [Fact]
    public async Task TwoIssuers_EachCrlListsOnlyItsOwnRevocations_SignedByItself()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var legacyId = await host.DefaultIssuerIdAsync(Ct);
        var second = await host.Kit.AddOnlineRootAsync("Second");
        await host.Registry.InvalidateAsync(Ct);
        var secondGen = host.Kit.NewGenerator(host.Kit.Storage.OptionsFor(second));
        var legacySerial = await host.SeedIssuedAsync(legacyId, host.Kit.Legacy, revoked: true, Ct);
        var secondSerial = await host.SeedIssuedAsync(second.Id, secondGen, revoked: true, Ct);
        var client = host.Anonymous();

        var legacyCrl = new X509CrlParser().ReadCrl(await client.GetByteArrayAsync("/crl", Ct));
        var secondCrl = new X509CrlParser().ReadCrl(await client.GetByteArrayAsync($"/crl/{second.Id}", Ct));

        Assert.NotNull(legacyCrl.GetRevokedCertificate(new BigInteger(legacySerial, 16)));
        Assert.Null(legacyCrl.GetRevokedCertificate(new BigInteger(secondSerial, 16)));
        Assert.NotNull(secondCrl.GetRevokedCertificate(new BigInteger(secondSerial, 16)));
        Assert.Null(secondCrl.GetRevokedCertificate(new BigInteger(legacySerial, 16)));
        Assert.Contains("CN=Second", secondCrl.IssuerDN.ToString());
        Assert.True(secondCrl.IsSignatureValid(QertumKeyCodec.VerifierFor(
            QertumKeyCodec.PublicKeyOf(QertumKeyCodec.ReadCertificatePem(second.CertificatePem!)!))));
    }

    [Fact]
    public async Task LegacyCrl_KeepsTheSettingsCounter_OtherIssuersCountOnTheirOwn()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await using (var db = host.Kit.Database.CreateContext())
        {
            (await db.Settings.SingleAsync(Ct)).CrlNumber = 41;
            await db.SaveChangesAsync(Ct);
        }
        await host.DefaultIssuerIdAsync(Ct); // bootstrap the legacy issuer before adding another
        var second = await host.Kit.AddOnlineRootAsync("Counted");
        await host.Registry.InvalidateAsync(Ct);
        var client = host.Anonymous();

        var legacy = new X509CrlParser().ReadCrl(await client.GetByteArrayAsync("/crl", Ct));
        var other = new X509CrlParser().ReadCrl(await client.GetByteArrayAsync($"/crl/{second.Id}", Ct));

        Assert.Equal(42, CrlNumberOf(legacy));
        Assert.Equal(1, CrlNumberOf(other));
    }

    [Fact]
    public async Task UnknownIssuer_Is404_AndPendingIssuerIs503()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct); // bootstrap first, so the pending row is not the only row
        var pending = IssuerModelTests.Row("Pending", status: IssuerStatus.PendingCertificate);
        await using (var db = host.Kit.Database.CreateContext()) { db.Issuers.Add(pending); await db.SaveChangesAsync(Ct); }
        await host.Registry.InvalidateAsync(Ct);
        var client = host.Anonymous();

        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync($"/crl/{Guid.NewGuid()}", Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.GetAsync($"/crl/{pending.Id}", Ct)).StatusCode);
    }

    [Fact]
    public async Task RetiredIssuer_StillPublishes()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var retired = await host.Kit.AddOnlineRootAsync("Retired", status: IssuerStatus.Retired);
        await host.Registry.InvalidateAsync(Ct);

        var response = await host.Anonymous().GetAsync($"/v1/crl/{retired.Id}", Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task ResetBase_ForANamedIssuer_RecordsItsOwnBase()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        await host.DefaultIssuerIdAsync(Ct);
        var second = await host.Kit.AddOnlineRootAsync("Based");
        await host.Registry.InvalidateAsync(Ct);

        var reset = await (await host.Admin().PostAsync($"/v1/crl/reset-base?issuerId={second.Id}", null, Ct))
            .Content.ReadFromJsonAsync<CrlBaseResetResponse>(Ct);

        await using var db = host.Kit.Database.CreateContext();
        Assert.Equal(reset!.CrlNumber, (await db.Issuers.SingleAsync(i => i.Id == second.Id, Ct)).BaseCrlNumber);
        Assert.Null((await db.Settings.SingleOrDefaultAsync(Ct))?.BaseCrlNumber);
    }

    [Fact]
    public async Task ConsumerEviction_DropsOnlyTheRevokedRowsIssuerKeys()
    {
        using var kit = new IssuerTestKit();
        kit.InitializeLegacy();
        var registry = kit.NewRegistry();
        await registry.GetDefaultAsync(Ct);
        var second = await kit.AddOnlineRootAsync("Evicted");
        await registry.InvalidateAsync(Ct);
        var cache = kit.Cache;
        await cache.SetAsync(CrlCache.Key, [1], Ct);
        await cache.SetAsync(CrlCache.KeyFor(second), [2], Ct);
        await cache.SetAsync(CrlCache.DeltaKeyFor(second), [3], Ct);

        await CertificateRequestQueueConsumer.EvictCrlAsync(cache, registry,
            new CertificateRequest { CommonName = "r", IssuerId = second.Id }, Ct);

        Assert.NotNull(await cache.GetAsync(CrlCache.Key, Ct));
        Assert.Null(await cache.GetAsync(CrlCache.KeyFor(second), Ct));
        Assert.Null(await cache.GetAsync(CrlCache.DeltaKeyFor(second), Ct));
    }

    private static long CrlNumberOf(X509Crl crl) =>
        DerInteger.GetInstance(X509ExtensionUtilities.FromExtensionValue(crl.GetExtensionValue(X509Extensions.CrlNumber))).LongValueExact;
}
