using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class IssuerRolloverTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static async Task<(IssuerApiHost Host, IssuerId Legacy, Issuer Next)> TwoRootsAsync()
    {
        var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var legacy = await host.DefaultIssuerIdAsync(Ct);
        var next = await host.Kit.AddOnlineRootAsync("Next Root");
        await host.Registry.InvalidateAsync(Ct);
        return (host, legacy, next);
    }

    [Fact]
    public async Task MakeDefault_SwitchesNewIssuance_OldStaysActive()
    {
        var (host, legacy, next) = await TwoRootsAsync();
        await using var _ = host;

        var response = await host.Admin().PostAsync($"/v1/issuers/{next.Id}/make-default", null, Ct);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(next.Id, await host.DefaultIssuerIdAsync(Ct));
        var old = await host.Admin().GetFromJsonAsync<IssuerResponse>($"/v1/issuers/{legacy}", Ct);
        Assert.Equal(IssuerStatus.Active, old!.Status);
        Assert.False(old.IsDefault);
    }

    [Fact]
    public async Task MakeDefault_OfAnOfflineOrPendingIssuer_Is409()
    {
        var (host, _, _) = await TwoRootsAsync();
        await using var _h = host;
        var offline = IssuerModelTests.Row("Offline");
        offline.KeyCustody = IssuerKeyCustody.Offline;
        offline.CertificatePem = host.Kit.Legacy.GetCaCertificatePem();
        var pending = IssuerModelTests.Row("Pending", status: IssuerStatus.PendingCertificate);
        await using (var db = host.Kit.Database.CreateContext()) { db.Issuers.AddRange(offline, pending); await db.SaveChangesAsync(Ct); }
        await host.Registry.InvalidateAsync(Ct);

        Assert.Equal(HttpStatusCode.Conflict, (await host.Admin().PostAsync($"/v1/issuers/{offline.Id}/make-default", null, Ct)).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await host.Admin().PostAsync($"/v1/issuers/{pending.Id}/make-default", null, Ct)).StatusCode);
    }

    [Fact]
    public async Task Retire_TheDefault_Is409_ElseRetiredAndStillAnswersCrl()
    {
        var (host, legacy, next) = await TwoRootsAsync();
        await using var _ = host;

        Assert.Equal(HttpStatusCode.Conflict, (await host.Admin().PostAsync($"/v1/issuers/{legacy}/retire", null, Ct)).StatusCode);
        (await host.Admin().PostAsync($"/v1/issuers/{next.Id}/make-default", null, Ct)).EnsureSuccessStatusCode();
        var retired = await (await host.Admin().PostAsync($"/v1/issuers/{legacy}/retire", null, Ct)).Content.ReadFromJsonAsync<IssuerResponse>(Ct);

        Assert.Equal(IssuerStatus.Retired, retired!.Status);
        Assert.Equal(HttpStatusCode.OK, (await host.Anonymous().GetAsync($"/crl/{legacy}", Ct)).StatusCode);
    }

    [Fact]
    public async Task Archive_WithUnexpiredCertificates_Is409WithTheCount_ElseArchivedAndKeyDeleted()
    {
        var (host, legacy, next) = await TwoRootsAsync();
        await using var _ = host;
        var nextGen = host.Kit.NewGenerator(host.Kit.Storage.OptionsFor(next));
        await host.SeedIssuedAsync(next.Id, nextGen, revoked: false, Ct);
        (await host.Admin().PostAsync($"/v1/issuers/{next.Id}/retire", null, Ct)).EnsureSuccessStatusCode();

        var refused = await host.Admin().PostAsync($"/v1/issuers/{next.Id}/archive", null, Ct);
        Assert.Equal(HttpStatusCode.Conflict, refused.StatusCode);
        Assert.Contains("1 unexpired", await refused.Content.ReadAsStringAsync(Ct));

        await using (var db = host.Kit.Database.CreateContext())
            await db.CertificateRequests.Where(r => r.IssuerId == next.Id)
                .ExecuteUpdateAsync(x => x.SetProperty(r => r.ValidTo, DateTime.UtcNow.AddDays(-1)), Ct);
        var archived = await host.Admin().PostAsync($"/v1/issuers/{next.Id}/archive", null, Ct);

        Assert.Equal(HttpStatusCode.OK, archived.StatusCode);
        Assert.False(host.Kit.Storage.HasKeyFile(next));
        Assert.Equal(HttpStatusCode.NotFound, (await host.Anonymous().GetAsync($"/crl/{next.Id}", Ct)).StatusCode);
    }

    [Fact]
    public async Task Archive_CountsARevokedButUnexpiredCertificate()
    {
        var (host, _, next) = await TwoRootsAsync();
        await using var _h = host;
        await host.SeedIssuedAsync(next.Id, host.Kit.NewGenerator(host.Kit.Storage.OptionsFor(next)), revoked: true, Ct);
        (await host.Admin().PostAsync($"/v1/issuers/{next.Id}/retire", null, Ct)).EnsureSuccessStatusCode();

        Assert.Equal(HttpStatusCode.Conflict, (await host.Admin().PostAsync($"/v1/issuers/{next.Id}/archive", null, Ct)).StatusCode);
    }

    [Fact]
    public async Task UnprefixedCrl_StaysTheLegacyIssuers_AfterRollover_UntilItIsArchived()
    {
        var (host, legacy, next) = await TwoRootsAsync();
        await using var _ = host;
        var legacyDn = Org.BouncyCastle.Asn1.X509.X509Name.GetInstance(
            Qertum.Services.Crypto.QertumKeyCodec.ReadCertificatePem(host.Kit.Legacy.GetCaCertificatePem())!.SubjectDN.ToAsn1Object());
        (await host.Admin().PostAsync($"/v1/issuers/{next.Id}/make-default", null, Ct)).EnsureSuccessStatusCode();

        async Task<Org.BouncyCastle.Asn1.X509.X509Name> CrlIssuerAsync(string path) =>
            new Org.BouncyCastle.X509.X509CrlParser().ReadCrl(await host.Anonymous().GetByteArrayAsync(path, Ct)).IssuerDN;

        // Legacy leaves' CDP is CaSettings.CrlDistributionPoint (= /crl): it must keep naming their CA.
        Assert.True((await CrlIssuerAsync("/crl")).Equivalent(legacyDn));
        (await host.Admin().PostAsync($"/v1/issuers/{legacy}/retire", null, Ct)).EnsureSuccessStatusCode();
        Assert.True((await CrlIssuerAsync("/crl")).Equivalent(legacyDn));

        (await host.Admin().PostAsync($"/v1/issuers/{legacy}/archive", null, Ct)).EnsureSuccessStatusCode();
        Assert.Contains("CN=Next Root", (await CrlIssuerAsync("/crl")).ToString());
    }

    [Theory]
    [InlineData("make-default")]
    [InlineData("retire")]
    [InlineData("archive")]
    public async Task LifecycleRoutes_RequireAdminRole(string action)
    {
        var (host, _, next) = await TwoRootsAsync();
        await using var _ = host;
        await host.GrantAsync("ops", AppPermissions.SettingsEdit, AppPermissions.PoliciesPublish);

        var response = await host.Role("ops").PostAsync($"/v1/issuers/{next.Id}/{action}", null, Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }
}
