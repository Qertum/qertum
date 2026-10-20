using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Qertum.Services;
using Qertum.Services.Crypto;
using Qertum.Services.Issuers;

namespace Qertum.Tests.Issuers;

public sealed class CreateIntermediateTests
{
    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static CreateIntermediateRequest Body(IssuerId? parent = null, string name = "Issuing CA 1") => new()
    {
        Name = name,
        CommonName = name,
        OrganizationName = "Qertum",
        KeyAlgorithm = CertificateKeyAlgorithm.EcdsaP256,
        ValidityDays = 1825,
        PathLength = 0,
        PermittedDnsSuffixes = ["corp.example"],
        ParentIssuerId = parent
    };

    [Fact]
    public async Task OnlineParent_SignsImmediately()
    {
        await using var host = new IssuerApiHost();
        host.Kit.InitializeLegacy();
        var root = await host.DefaultIssuerIdAsync(Ct);

        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", Body(root), Ct);
        var created = await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Null(created!.RequestFile);
        Assert.Equal(IssuerStatus.Active, created.Issuer.Status);
        Assert.Equal(IssuerKeyCustody.Online, created.Issuer.KeyCustody);
        Assert.Equal(root, created.Issuer.ParentIssuerId);
        Assert.Equal(["corp.example"], created.Issuer.PermittedDnsSuffixes);
        Assert.Equal(0, created.Issuer.PathLengthConstraint);
        Assert.False(created.Issuer.IsDefault); // a default already exists
        var handle = await host.Registry.GetAsync(created.Issuer.Id, Ct);
        Assert.True(handle!.CanIssue);
    }

    [Fact]
    public async Task NoParent_IsPendingWithARequestFile_AndTheKeyStaysEncryptedOnDisk()
    {
        await using var host = new IssuerApiHost();

        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", Body(), Ct);
        var created = await response.Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct);

        Assert.Equal(IssuerStatus.PendingCertificate, created!.Issuer.Status);
        var file = created.RequestFile!;
        Assert.Equal(IntermediateRequestFile.CurrentFormat, file.Format);
        Assert.Equal(created.Issuer.Id, file.IssuerId);
        Assert.Equal(["corp.example"], file.PermittedDnsSuffixes);
        var csr = QertumKeyCodec.ReadCertificationRequestPem(file.CsrPem);
        Assert.True(QertumKeyCodec.VerifySelfSignature(csr));
        var row = await ReadRowAsync(host, created.Issuer.Id);
        var keyText = await File.ReadAllTextAsync(host.Kit.Storage.KeyPath(row), Ct);
        Assert.DoesNotContain("PRIVATE KEY", keyText);
        Assert.False(File.Exists(host.Kit.Storage.CertificatePath(row)));

        var again = await host.Admin().GetFromJsonAsync<IntermediateRequestFile>($"/v1/issuers/{created.Issuer.Id}/request", Ct);
        Assert.Equal(file.CsrPem, again!.CsrPem);
    }

    [Fact]
    public async Task RequiresAdminRole()
    {
        await using var host = new IssuerApiHost();
        await host.GrantAsync("ops", AppPermissions.SettingsEdit, AppPermissions.PoliciesPublish, AppPermissions.CertificatesManage);

        var response = await host.Role("ops").PostAsJsonAsync("/v1/issuers/intermediates", Body(), Ct);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Theory]
    [InlineData(CertificateKeyAlgorithm.HybridEcdsaP256)]
    [InlineData(CertificateKeyAlgorithm.MlKem768)]
    public async Task NonSigningOrPairedAlgorithms_Are400(CertificateKeyAlgorithm algorithm)
    {
        await using var host = new IssuerApiHost();
        var body = Body();
        body.KeyAlgorithm = algorithm;

        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", body, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("*.corp.example", null)]
    [InlineData("corp..example", null)]
    [InlineData(null, "10.0.0.0/33")]
    [InlineData(null, "not-an-ip")]
    public async Task MalformedConstraints_Are400(string? dns, string? ip)
    {
        await using var host = new IssuerApiHost();
        var body = Body();
        body.PermittedDnsSuffixes = dns is null ? [] : [dns];
        body.PermittedIpRanges = ip is null ? [] : [ip];

        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", body, Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task PqcOnly_RefusesAClassicalIntermediate()
    {
        await using var host = new IssuerApiHost();
        await using (var db = host.Kit.Database.CreateContext())
        {
            (await db.Settings.SingleAsync(Ct)).PqcStage = PqcStage.Enforce;
            await db.SaveChangesAsync(Ct);
        }

        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", Body(), Ct);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task DuplicateName_Is409()
    {
        await using var host = new IssuerApiHost();
        await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", Body(name: "Dup"), Ct);

        var second = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", Body(name: "Dup"), Ct);

        Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
    }

    [Fact]
    public async Task RetiredParent_Is409()
    {
        await using var host = new IssuerApiHost();
        var retired = await host.Kit.AddOnlineRootAsync("Retired Parent", status: IssuerStatus.Retired);

        var response = await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", Body(retired.Id), Ct);

        Assert.Equal(HttpStatusCode.Conflict, response.StatusCode);
    }

    [Fact]
    public async Task DeletePending_RemovesRowAndKey_ButActiveIs409()
    {
        await using var host = new IssuerApiHost();
        var created = await (await host.Admin().PostAsJsonAsync("/v1/issuers/intermediates", Body(), Ct))
            .Content.ReadFromJsonAsync<CreateIntermediateResponse>(Ct);
        var row = await ReadRowAsync(host, created!.Issuer.Id);

        var deleted = await host.Admin().DeleteAsync($"/v1/issuers/{row.Id}", Ct);

        Assert.Equal(HttpStatusCode.NoContent, deleted.StatusCode);
        Assert.False(File.Exists(host.Kit.Storage.KeyPath(row)));
        await using (var db = host.Kit.Database.CreateContext())
            Assert.False(await db.Issuers.AnyAsync(i => i.Id == row.Id, Ct));

        host.Kit.InitializeLegacy();
        var active = await host.DefaultIssuerIdAsync(Ct);
        Assert.Equal(HttpStatusCode.Conflict, (await host.Admin().DeleteAsync($"/v1/issuers/{active}", Ct)).StatusCode);
    }

    private static async Task<Issuer> ReadRowAsync(IssuerApiHost host, IssuerId id)
    {
        await using var db = host.Kit.Database.CreateContext();
        return await db.Issuers.AsNoTracking().SingleAsync(i => i.Id == id, Ct);
    }
}
